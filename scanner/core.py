import os
import re
import tempfile
import subprocess
from datetime import datetime
from models import Project, Log, Vulnerability
from extensions import db
from utils.ai_engine import generate_ai_suggestions


def _mock_fix_snippets(vuln_type):
    snippets = {
        'Hardcoded Secret': (
            "API_KEY = 'prod-secret-token-123'",
            "API_KEY = os.getenv('API_KEY')  # loaded from secure env/secret manager"
        ),
        'Insecure Eval': (
            "result = eval(user_input)",
            "allowed = {'sum': safe_sum, 'avg': safe_avg}\nresult = allowed[user_choice](numbers)"
        ),
        'SQL Injection Pattern': (
            "cursor.execute(f\"SELECT * FROM users WHERE email = '{email}'\")",
            "cursor.execute(\"SELECT * FROM users WHERE email = ?\", (email,))"
        )
    }
    return snippets.get(
        vuln_type,
        ("# vulnerable mock code", "# fixed mock code")
    )


def apply_mock_fixes(project_id):
    """Simulate an automatic fix pipeline without touching real source repos."""
    open_vulns = Vulnerability.query.filter_by(project_id=project_id, is_fixed=False).all()
    fixed_count = 0

    for vuln in open_vulns:
        before_code, after_code = _mock_fix_snippets(vuln.vuln_type)
        vuln.is_fixed = True
        vuln.mock_before_code = before_code
        vuln.mock_after_code = after_code
        vuln.fixed_at = datetime.utcnow()
        fixed_count += 1

        db.session.add(Log(
            project_id=project_id,
            action_type='FIX_APPLIED',
            detail=f"Mock auto-fix applied for {vuln.vuln_type} at {vuln.endpoint}. Status moved to Fixed."
        ))

    db.session.add(Log(
        project_id=project_id,
        action_type='AUTOFIX_COMPLETED',
        detail=f"Automatic mock remediation completed. {fixed_count} vulnerabilities marked as Fixed."
    ))
    db.session.commit()
    return fixed_count


def run_scan(project_id):
    """
    Simulates a SAST vulnerability scan on a GitHub repository.
    """
    project = Project.query.get(project_id)
    if not project or not project.consent_granted:
        return False
        
    repo_url = project.target_url

    log = Log(project_id=project.id, action_type='SCAN_STARTED', detail=f'Started cloning repository from {repo_url}')
    db.session.add(log)
    db.session.commit()
    
    # regex patterns for hackathon SAST
    patterns = {
        'Hardcoded Secret': {
            'regex': re.compile(r"(?i)(api_key|token|password|secret)\s*=\s*(['\"][A-Za-z0-9_\-]+['\"])", re.IGNORECASE),
            'desc': 'Detected a potential hardcoded secret in the source code.'
        },
        'Insecure Eval': {
            'regex': re.compile(r"eval\s*\(", re.IGNORECASE),
            'desc': 'Usage of eval() detected, which can lead to remote code execution.'
        },
        'SQL Injection Pattern': {
            'regex': re.compile(r"execute\s*\(\s*f['\"].*?\{.*?\}.*?['\"]\s*\)", re.IGNORECASE),
            'desc': 'SQL Query uses f-string interpolation instead of parameterized queries.'
        }
    }

    try:
        # Securely orchestrate the cloning in a temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Clone the repo securely without hanging on interactive prompts
                env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
                result = subprocess.run(['git', 'clone', repo_url, temp_dir], capture_output=True, text=True, timeout=15, env=env)
                if result.returncode != 0:
                    raise Exception(f"Git clone failed: {result.stderr}")
            except Exception as e:
                log = Log(project_id=project.id, action_type='SCAN_ERROR', detail=f'Failed to clone repo: {str(e)[:200]}')
                db.session.add(log)
                db.session.commit()
                return False

            log = Log(project_id=project.id, action_type='SCAN_INFO', detail='Repository cloned securely. Starting static analysis.')
            db.session.add(log)
            db.session.commit()

            # Walk through the directory seeking py, js, and html files
            files_scanned = 0
            for root, dirs, files in os.walk(temp_dir):
                # Ignore common overhead directories to optimize speed
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', 'build', 'dist']]
                
                for file in files:
                    if file.endswith(('.py', '.js', '.html')):
                        files_scanned += 1
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, temp_dir)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                
                                for vuln_type, p_info in patterns.items():
                                    matches = p_info['regex'].findall(content)
                                    if matches:
                                        payload_str = str(matches[0])[:150]
                                        
                                        log = Log(project_id=project.id, action_type='SCAN_ATTACK', detail=f'Analyzing pattern {vuln_type} in {relative_path}')
                                        db.session.add(log)
                                        db.session.commit()
                                        
                                        # Generate dynamic AI response via Gemini
                                        ai_exp, fix_sugg = generate_ai_suggestions(
                                            vuln_type=vuln_type,
                                            endpoint=relative_path,
                                            payload=payload_str,
                                            description=p_info['desc']
                                        )
                                        
                                        v = Vulnerability(
                                            project_id=project.id,
                                            vuln_type=vuln_type,
                                            endpoint=relative_path,
                                            payload=payload_str,
                                            description=p_info['desc'],
                                            ai_explanation=ai_exp,
                                            fix_suggestion=fix_sugg
                                        )
                                        db.session.add(v)
                                        db.session.commit()
                                        
                                        log = Log(project_id=project.id, action_type='VULN_FOUND', detail=f'Detected {vuln_type} in {relative_path}')
                                        db.session.add(log)
                        except Exception:
                            # Safely skip unreadable files
                            pass

            log = Log(project_id=project.id, action_type='SCAN_COMPLETED', detail=f'Finished static scan across {files_scanned} files. Cloned repository has been purged.')
            db.session.add(log)
            db.session.commit()

            db.session.add(Log(
                project_id=project.id,
                action_type='AUTOFIX_STARTED',
                detail='Scan finished. Triggering automatic mock remediation pipeline.'
            ))
            db.session.commit()

            apply_mock_fixes(project.id)
            
        return True
    
    except Exception as e:
        log = Log(project_id=project.id, action_type='SCAN_ERROR', detail=f'Scan logic crashed: {str(e)[:200]}')
        db.session.add(log)
        db.session.commit()
        return False
