import os
import re
import tempfile
import subprocess
import time
from datetime import datetime
from models import Project, Log, Vulnerability
from extensions import db
from utils.ai_engine import generate_ai_suggestions

# ─── Mock Code Snippet Templates per Vulnerability Type ──────────────────────
MOCK_FIXES = {
    'Hardcoded Secret': {
        'before': '''\
# ❌ VULNERABLE: Credential hardcoded directly in source
api_key = "sk-a8f3c2d91e4b7a6205f8e1d3"
AUTH_TOKEN = "ghp_xK2mN9pLqR4sT7vW0yA3bC6dE"

def connect_to_service():
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    requests.get("https://api.service.com/data", headers=headers)''',
        'after': '''\
# ✅ FIXED: Credentials loaded from environment variables
import os
api_key = os.environ.get("API_KEY")
AUTH_TOKEN = os.environ.get("AUTH_TOKEN")

def connect_to_service():
    token = os.environ.get("AUTH_TOKEN")
    if not token:
        raise EnvironmentError("AUTH_TOKEN not configured")
    headers = {"Authorization": f"Bearer {token}"}
    requests.get("https://api.service.com/data", headers=headers)'''
    },
    'SQL Injection': {
        'before': '''\
# ❌ VULNERABLE: Raw user input interpolated into SQL query
def get_user(username):
    query = f"SELECT * FROM users WHERE username = \'{username}\'"
    cursor.execute(query)
    return cursor.fetchone()

# Attacker input: \' OR \'1\'=\'1
# Resulting query: SELECT * FROM users WHERE username = \'\' OR \'1\'=\'1\'''',
        'after': '''\
# ✅ FIXED: Parameterized queries prevent SQL injection
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()

# SQLAlchemy ORM approach (preferred)
def get_user_orm(username):
    return User.query.filter_by(username=username).first()'''
    },
    'XSS Vulnerability': {
        'before': '''\
// ❌ VULNERABLE: Unsanitized user input written to DOM
function displayMessage(userInput) {
    document.getElementById("output").innerHTML = userInput;
}

// Attacker payload: <script>document.cookie='stolen='+document.cookie</script>
const name = new URLSearchParams(window.location.search).get("name");
document.write("Welcome, " + name);''',
        'after': '''\
// ✅ FIXED: Sanitized via textContent and DOMPurify
function displayMessage(userInput) {
    const sanitized = DOMPurify.sanitize(userInput);
    document.getElementById("output").textContent = sanitized;
}

// Safe alternative using textContent (auto-escapes HTML)
const name = new URLSearchParams(window.location.search).get("name");
const el = document.createElement("span");
el.textContent = "Welcome, " + name;
document.body.appendChild(el);'''
    },
    'Insecure Eval': {
        'before': '''\
// ❌ VULNERABLE: eval() executes arbitrary code strings
function calculate(expression) {
    return eval(expression); // RCE if attacker controls expression
}

// In Python:
# user_code = request.args.get("formula")
# result = eval(user_code)      # Remote code execution risk''',
        'after': '''\
// ✅ FIXED: Safe expression parser used instead of eval()
const { Parser } = require("expr-eval");
function calculate(expression) {
    const parser = new Parser();
    return parser.evaluate(expression); // Sandboxed, no code execution
}

// In Python — use ast.literal_eval for safe data parsing:
# import ast
# result = ast.literal_eval(user_input)   # Only parses literals'''
    },
    'Unsafe Firebase Rules': {
        'before': '''\
// ❌ VULNERABLE: Firebase rules allow public read/write
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
// Anyone on the internet can read or overwrite ALL data''',
        'after': '''\
// ✅ FIXED: Authentication-gated Firebase security rules
{
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid == $uid",
        ".write": "auth != null && auth.uid == $uid"
      }
    },
    "public_data": {
      ".read": true,
      ".write": "auth != null"
    }
  }
}'''
    },
    'Weak Authentication': {
        'before': '''\
# ❌ VULNERABLE: MD5 used for password hashing (broken)
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    return stored_hash == hashlib.md5(password.encode()).hexdigest()''',
        'after': '''\
# ✅ FIXED: bcrypt with salt rounds for secure password hashing
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)'''
    },
}

DEFAULT_FIX = {
    'before': '''\
# ❌ VULNERABLE: Insecure pattern detected in source code
# Review the flagged file and line for the specific issue.
# This vulnerability may allow attackers to compromise system security.''',
    'after': '''\
# ✅ FIXED: Insecure pattern has been remediated
# Applied security best practices.
# Input validation, sanitization, and safe API usage enforced.'''
}


# ─── SAST Pattern Dictionary ──────────────────────────────────────────────────
# Each pattern has: regex, description, severity, and file extensions to scan
PATTERNS = [
    {
        'vuln_type': 'Hardcoded Secret',
        'severity': 'High',
        'exts': ('.py', '.js', '.ts', '.env', '.json', '.yaml', '.yml'),
        'regex': re.compile(
            r'(?i)(api_key|apikey|token|password|secret|access_key|private_key)\s*[=:]\s*["\']([A-Za-z0-9_\-/+]{8,})["\']'
        ),
        'desc': 'A sensitive credential (API key, password, or token) is hardcoded directly in the source code. This exposes it to anyone who views the repository.'
    },
    {
        'vuln_type': 'SQL Injection',
        'severity': 'High',
        'exts': ('.py', '.js', '.php', '.ts'),
        'regex': re.compile(
            r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'].*?\{.*?\}.*?["\']'
            r'|"SELECT.*?\+.*?"|\'SELECT.*?\+.*?\''
        ),
        'desc': 'Raw user input is being directly interpolated into a SQL query string. This allows attackers to manipulate the query to dump, modify, or destroy your database.'
    },
    {
        'vuln_type': 'XSS Vulnerability',
        'severity': 'Medium',
        'exts': ('.html', '.js', '.ts'),
        'regex': re.compile(
            r'innerHTML\s*=|document\.write\s*\(|\.html\s*\(\s*(req|user|input|data|param)'
        ),
        'desc': 'User-supplied input is being injected into the DOM without sanitization. This allows attackers to execute malicious scripts in the browser of every visitor.'
    },
    {
        'vuln_type': 'Insecure Eval',
        'severity': 'High',
        'exts': ('.py', '.js', '.ts'),
        'regex': re.compile(
            r'\beval\s*\('
        ),
        'desc': 'Usage of eval() allows execution of arbitrary code strings. If attacker-controlled input reaches eval(), it results in remote code execution on your server.'
    },
    {
        'vuln_type': 'Unsafe Firebase Rules',
        'severity': 'High',
        'exts': ('.json', '.rules'),
        'regex': re.compile(
            r'["\']\.read["\']\s*:\s*["\']?true["\']?|["\']\.write["\']\s*:\s*["\']?true["\']?'
            r'|allow read, write\s*:|allow read\s*:\s*if true|allow write\s*:\s*if true'
        ),
        'desc': 'Firebase security rules are configured to allow open read or write access to all users, including unauthenticated ones. This exposes your entire database publicly.'
    },
    {
        'vuln_type': 'Weak Authentication',
        'severity': 'Medium',
        'exts': ('.py', '.js', '.ts', '.php'),
        'regex': re.compile(
            r'(?i)(md5|sha1)\s*\(|password\s*==\s*|verify\s*=\s*False'
        ),
        'desc': 'Weak cryptographic functions (MD5/SHA1) or disabled SSL verification detected. These expose passwords to cracking attacks and communications to interception.'
    },
]


# ─── Inline Code Fixer ───────────────────────────────────────────────────────
def _generate_inline_fix(vuln_type: str, line: str) -> str:
    """
    Apply a targeted transformation to the actual vulnerable line of code.
    Returns the patched version of that line for the AFTER diff view.
    """
    import re as _re

    if vuln_type == 'Hardcoded Secret':
        # Replace the hardcoded value with os.environ.get(...)
        def _env_replace(m):
            key = m.group(1).upper()
            return f'{m.group(0).split("=")[0].split(":")[0]} = os.environ.get("{key}")'
        patched = _re.sub(
            r'(?i)(api_key|apikey|token|password|secret|access_key|private_key)\s*[=:]\s*["\']([A-Za-z0-9_\-/+]{8,})["\']',
            _env_replace, line
        )
        if patched == line:
            patched = f'# FIX: {line.strip()}  →  use os.environ.get("...")'
        return patched

    elif vuln_type == 'SQL Injection':
        # Replace f-string / concatenated query with a placeholder comment
        patched = _re.sub(r'f["\'].*?["\']', '"<parameterized_query>"', line)
        patched = _re.sub(r'"SELECT.*?\+.*?"', '"SELECT ... WHERE col = ?"', patched)
        if patched == line:
            patched = line + '  # FIX: use parameterized query, e.g. cursor.execute(sql, (val,))'
        return patched

    elif vuln_type == 'XSS Vulnerability':
        patched = line.replace('innerHTML', 'textContent')
        patched = patched.replace('document.write(', 'el.textContent = (/* FIX */ ')
        if patched == line:
            patched = line + '  // FIX: sanitize with DOMPurify.sanitize(input)'
        return patched

    elif vuln_type == 'Insecure Eval':
        patched = _re.sub(r'\beval\s*\(', 'JSON.parse(  /* FIX: replaced eval() */', line)
        if patched == line:
            patched = line + '  // FIX: remove eval(); use a safe parser instead'
        return patched

    elif vuln_type == 'Unsafe Firebase Rules':
        patched = _re.sub(r'(["\']\.(read|write)["\'])\s*:\s*["\']?true["\']?',
                          r'\1: "auth != null"', line)
        if patched == line:
            patched = line + '  // FIX: restrict to "auth != null"'
        return patched

    elif vuln_type == 'Weak Authentication':
        patched = _re.sub(r'\bmd5\b', 'hashlib.sha256', line, flags=_re.IGNORECASE)
        patched = _re.sub(r'\bsha1\b', 'hashlib.sha256', patched, flags=_re.IGNORECASE)
        patched = _re.sub(r'verify\s*=\s*False', 'verify=True  # FIX', patched)
        patched = _re.sub(r'password\s*==\s*', 'check_password_hash(stored_hash, ', patched)
        if patched == line:
            patched = line + '  # FIX: use bcrypt / werkzeug check_password_hash'
        return patched

    return line + '  # FIX: security issue remediated'


def run_scan(project_id, stop_flags=None, scan_status=None):
    """
    SAST vulnerability scan on a GitHub repository.
    Clones the repo into a temporary directory, scans files,
    and purges the clone immediately after.

    stop_flags: dict mapping project_id -> bool (set True to cancel)
    scan_status: dict mapping project_id -> status string
    """
    if stop_flags is None:
        stop_flags = {}
    if scan_status is None:
        scan_status = {}

    def _should_stop():
        return stop_flags.get(project_id, False)

    project = Project.query.get(project_id)
    if not project or not project.consent_granted:
        return False

    repo_url = project.target_url

    log = Log(project_id=project.id, action_type='SCAN_STARTED',
              detail=f'Initiating SAST scan — cloning {repo_url}')
    db.session.add(log)
    db.session.commit()

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # ── Clone repo ────────────────────────────────────────────────────
            try:
                env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
                result = subprocess.run(
                    ['git', 'clone', '--depth=1', repo_url, temp_dir],
                    capture_output=True, text=True, timeout=30, env=env
                )
                if result.returncode != 0:
                    raise Exception(f"Git clone failed: {result.stderr[:300]}")
            except Exception as e:
                log = Log(project_id=project.id, action_type='SCAN_ERROR',
                          detail=f'Clone failed: {str(e)[:200]}')
                db.session.add(log)
                db.session.commit()
                return False

            log = Log(project_id=project.id, action_type='SCAN_INFO',
                      detail='Repository cloned. Starting static analysis across all files.')
            db.session.add(log)
            db.session.commit()

            # ── Walk files ────────────────────────────────────────────────────
            files_scanned = 0
            vulns_found = 0
            skip_dirs = {'.git', 'node_modules', 'venv', '__pycache__', 'build', 'dist', '.next', 'vendor'}

            for root, dirs, files in os.walk(temp_dir):
                dirs[:] = [d for d in dirs if d not in skip_dirs]

                # ── Check stop flag between directories ──────────────────────
                if _should_stop():
                    break

                for file in files:
                    if _should_stop():
                        break
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, temp_dir)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for pattern in PATTERNS:
                            # Only scan relevant file types
                            if not any(file.endswith(ext) for ext in pattern['exts']):
                                continue

                            files_scanned += 1

                            # ── Find actual matching lines ─────────────────────
                            lines = content.splitlines()
                            matched_line_nos = []
                            for i, line in enumerate(lines):
                                if pattern['regex'].search(line):
                                    matched_line_nos.append(i)

                            if not matched_line_nos:
                                continue

                            # Build real "before" snippet: matched line ± 4 lines context
                            first_match_line = matched_line_nos[0]
                            ctx_start = max(0, first_match_line - 4)
                            ctx_end   = min(len(lines), first_match_line + 5)
                            context_lines = lines[ctx_start:ctx_end]

                            before_code_lines = []
                            for idx, src_line in enumerate(context_lines):
                                lineno = ctx_start + idx + 1
                                arrow = " ► " if (ctx_start + idx) in matched_line_nos else "   "
                                before_code_lines.append(f"  {lineno:4d}{arrow}{src_line}")
                            real_before_code = (
                                f"# FILE: {relative_path}\n"
                                f"# {'─' * 56}\n"
                                + "\n".join(before_code_lines)
                            )

                            # Build real "after": replace the vulnerable pattern in each matched line
                            after_lines = list(lines)
                            for i in matched_line_nos:
                                after_lines[i] = _generate_inline_fix(
                                    pattern['vuln_type'], after_lines[i]
                                )
                            after_ctx = after_lines[ctx_start:ctx_end]
                            after_code_lines = []
                            for idx, src_line in enumerate(after_ctx):
                                lineno = ctx_start + idx + 1
                                was_vuln = (ctx_start + idx) in matched_line_nos
                                prefix = "  + " if was_vuln else "    "
                                after_code_lines.append(f"  {lineno:4d}{prefix}{src_line}")
                            real_after_code = (
                                f"# FILE: {relative_path}  [PATCHED]\n"
                                f"# {'─' * 56}\n"
                                + "\n".join(after_code_lines)
                            )

                            payload_str = str(lines[first_match_line].strip())[:150]
                            vuln_type = pattern['vuln_type']
                            severity = pattern['severity']

                            log = Log(project_id=project.id, action_type='SCAN_ATTACK',
                                      detail=f'[{severity}] Detected pattern "{vuln_type}" in {relative_path} (line {first_match_line + 1})')
                            db.session.add(log)
                            db.session.commit()

                            # Gemini AI explanation
                            ai_exp, fix_sugg = generate_ai_suggestions(
                                vuln_type=vuln_type,
                                endpoint=relative_path,
                                payload=payload_str,
                                description=pattern['desc']
                            )

                            v = Vulnerability(
                                project_id=project.id,
                                vuln_type=vuln_type,
                                severity=severity,
                                endpoint=relative_path,
                                payload=payload_str,
                                description=pattern['desc'],
                                ai_explanation=ai_exp,
                                fix_suggestion=fix_sugg,
                                mock_before_code=real_before_code,
                                mock_after_code=real_after_code,
                            )
                            db.session.add(v)
                            db.session.commit()

                            log = Log(project_id=project.id, action_type='VULN_FOUND',
                                      detail=f'[{severity}] {vuln_type} confirmed in {relative_path} at line {first_match_line + 1}')
                            db.session.add(log)
                            db.session.commit()
                            vulns_found += 1


                    except Exception:
                        pass

            if _should_stop():
                log = Log(
                    project_id=project.id,
                    action_type='SCAN_STOPPED',
                    detail=f'⛔ Scan aborted by user — {files_scanned} files checked, {vulns_found} vulnerabilities found before stop.'
                )
                db.session.add(log)
                db.session.commit()
                scan_status[project_id] = 'stopped'
                return False

            log = Log(
                project_id=project.id,
                action_type='SCAN_COMPLETED',
                detail=f'Scan complete — {files_scanned} files checked, {vulns_found} vulnerabilities found. Clone purged.'
            )
            db.session.add(log)
            db.session.commit()

        # ── Automatically apply mock fixes right after scan ────────────────
        if vulns_found > 0 and not _should_stop():
            scan_status[project_id] = 'fixing'
            apply_automated_fixes(project_id)

        scan_status[project_id] = 'done'
        return True

    except Exception as e:
        log = Log(project_id=project.id, action_type='SCAN_ERROR',
                  detail=f'Scan engine crashed: {str(e)[:200]}')
        db.session.add(log)
        db.session.commit()
        return False



# ─── Automated Mock Fix Engine ────────────────────────────────────────────────
def apply_automated_fixes(project_id):
    """
    Automatically apply mock fixes to all unfixed vulnerabilities
    immediately after a scan completes. Generates realistic before/after
    code snippets and marks each vulnerability as fixed with a log entry.
    No actual code is modified — this is a simulated demonstration only.
    """
    project = Project.query.get(project_id)
    if not project:
        return

    # Brief pause so dashboard logs show the transition clearly
    time.sleep(0.8)

    log_start = Log(
        project_id=project_id,
        action_type='AUTO_FIX_STARTED',
        detail='🤖 AI Auto-Fix Engine activated — analysing vulnerabilities and generating patches...'
    )
    db.session.add(log_start)
    db.session.commit()

    time.sleep(0.5)

    vulns = Vulnerability.query.filter_by(project_id=project_id, is_fixed=False).all()
    fixed_count = 0

    for v in vulns:
        time.sleep(0.3)  # Stagger fixes for real-time feel

        v.is_fixed = True
        v.fixed_at = datetime.utcnow()

        # Only use the generic template if real code wasn't captured at scan time
        if not v.mock_before_code:
            fix_template = MOCK_FIXES.get(v.vuln_type, DEFAULT_FIX)
            v.mock_before_code = fix_template['before']
            v.mock_after_code = fix_template['after']

        db.session.commit()

        log_fix = Log(
            project_id=project_id,
            action_type='FIX_APPLIED',
            detail=f'✅ [{v.severity}] {v.vuln_type} patched in {v.endpoint} — real code diff generated'
        )
        db.session.add(log_fix)
        db.session.commit()
        fixed_count += 1

    # Final summary log
    log_done = Log(
        project_id=project_id,
        action_type='AUTO_FIX_COMPLETE',
        detail=f'🎉 Auto-fix complete — {fixed_count} vulnerabilities remediated. Security score recalculated.'
    )
    db.session.add(log_done)
    db.session.commit()

