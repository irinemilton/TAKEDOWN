import os
import re
import tempfile
import subprocess
from models import Project, Log, Vulnerability
from extensions import db
from utils.ai_engine import generate_ai_suggestions

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


def run_scan(project_id):
    """
    SAST vulnerability scan on a GitHub repository.
    Clones the repo into a temporary directory, scans files,
    and purges the clone immediately after.
    """
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

                for file in files:
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
                            matches = pattern['regex'].findall(content)
                            if not matches:
                                continue

                            payload_str = str(matches[0])[:150]
                            vuln_type = pattern['vuln_type']
                            severity = pattern['severity']

                            log = Log(project_id=project.id, action_type='SCAN_ATTACK',
                                      detail=f'[{severity}] Detected pattern "{vuln_type}" in {relative_path}')
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
                                fix_suggestion=fix_sugg
                            )
                            db.session.add(v)
                            db.session.commit()

                            log = Log(project_id=project.id, action_type='VULN_FOUND',
                                      detail=f'[{severity}] {vuln_type} confirmed in {relative_path}')
                            db.session.add(log)
                            db.session.commit()
                            vulns_found += 1

                    except Exception:
                        pass

            log = Log(
                project_id=project.id,
                action_type='SCAN_COMPLETED',
                detail=f'Scan complete — {files_scanned} files checked, {vulns_found} vulnerabilities found. Clone purged.'
            )
            db.session.add(log)
            db.session.commit()

        return True

    except Exception as e:
        log = Log(project_id=project.id, action_type='SCAN_ERROR',
                  detail=f'Scan engine crashed: {str(e)[:200]}')
        db.session.add(log)
        db.session.commit()
        return False
