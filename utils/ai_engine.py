import os
import google.generativeai as genai
from config import Config

# ─── API Key Setup ────────────────────────────────────────────────────────────
_API_KEY = Config.GEMINI_API_KEY
_GEMINI_AVAILABLE = bool(_API_KEY)

if _GEMINI_AVAILABLE:
    genai.configure(api_key=_API_KEY)
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
    except Exception:
        try:
            model = genai.GenerativeModel('gemini-pro')
        except Exception:
            _GEMINI_AVAILABLE = False
            model = None
else:
    model = None
    print("⚠️  [AI Engine] GEMINI_API_KEY not set — using built-in explanations.")

# ─── Offline Fallback Explanations ────────────────────────────────────────────
# Used when the Gemini API is unavailable or the key is missing.
_FALLBACKS = {
    'Hardcoded Secret': (
        "A secret credential (such as an API key, password, or token) is stored directly "
        "inside the source code. Anyone who can read this file — including collaborators, "
        "attackers who find the public repo, or anyone who decompiles the app — can steal "
        "and misuse this credential to access your systems or data.",
        "Move all credentials out of source code and into environment variables or a secrets "
        "manager (e.g. AWS Secrets Manager, HashiCorp Vault). Reference them with "
        "os.environ.get('KEY_NAME') and never commit .env files."
    ),
    'SQL Injection': (
        "Raw user input is being embedded directly into a SQL database query string. "
        "An attacker can type specially crafted text (e.g. ' OR '1'='1) that changes the "
        "meaning of the query, allowing them to bypass logins, read private data, "
        "delete records, or take over the database entirely.",
        "Use parameterized queries or prepared statements exclusively — never concatenate or "
        "f-string user input into SQL. With SQLAlchemy use the ORM or text() with :param bindings."
    ),
    'XSS Vulnerability': (
        "Unsanitized user-supplied content is being injected directly into a web page. "
        "An attacker can craft a URL or form input containing a malicious script tag that "
        "runs in every visitor's browser — stealing their session cookies, redirecting them "
        "to phishing sites, or silently capturing keystrokes.",
        "Never assign user input to innerHTML or use document.write(). Use textContent or "
        "innerText for plain text, and sanitize HTML with DOMPurify before rendering."
    ),
    'Insecure Eval': (
        "The eval() function is being called, which executes any string passed to it as "
        "live code. If an attacker can influence the input to eval(), they can run arbitrary "
        "commands on the server or in the browser — a direct path to full system compromise.",
        "Remove all eval() calls. Use JSON.parse() for JSON data, ast.literal_eval() for "
        "Python literals, or a dedicated expression-parsing library for math expressions."
    ),
    'Unsafe Firebase Rules': (
        "Your Firebase Realtime Database or Firestore rules allow anyone on the internet — "
        "even unauthenticated users — to read or write all data. This means any attacker "
        "can download your entire database, overwrite records, or inject malicious data "
        "without needing a login.",
        "Replace all 'true' read/write rules with auth-gated rules such as "
        "'auth != null && auth.uid == $uid'. Lock down every collection to the minimum "
        "required access and test with the Firebase Rules Simulator."
    ),
    'Weak Authentication': (
        "The application is using MD5 or SHA-1 to hash passwords, which are cryptographically "
        "broken algorithms. Modern GPUs can crack billions of MD5 hashes per second. An "
        "attacker who obtains your password database can reverse all passwords within hours "
        "using precomputed rainbow tables.",
        "Replace MD5/SHA1 with bcrypt, scrypt, or Argon2 for password hashing. In Python, "
        "use werkzeug.security.generate_password_hash() (which uses PBKDF2-SHA256) or "
        "the passlib/bcrypt library."
    ),
}

_DEFAULT_FALLBACK = (
    "A security vulnerability was detected in the scanned code. This issue could allow "
    "an attacker to gain unauthorized access, manipulate data, or compromise system integrity. "
    "Review the flagged file and line number carefully.",
    "Follow secure coding best practices for the detected vulnerability category. "
    "Consult the OWASP Top 10 guidelines at owasp.org for specific remediation steps."
)


def generate_ai_suggestions(vuln_type, endpoint, payload, description):
    """
    Calls the Gemini API to generate dynamic AI explanations and fix suggestions.
    Falls back to rich built-in explanations when the API key is missing or the
    API call fails.

    Returns: (ai_explanation: str, fix_suggestion: str)
    """
    if _GEMINI_AVAILABLE and model:
        prompt = f"""You are a cybersecurity expert explaining a security vulnerability in simple, plain English to a non-technical person.

A vulnerability was found during an automated security scan:
- Type: {vuln_type}
- File/Location: {endpoint}
- Code Found: {payload}
- Technical Detail: {description}

Write your response in EXACTLY two parts separated by "---FIX---".

PART 1 (Simple Explanation — 2 to 3 short sentences):
Start your first sentence with "This vulnerability allows attackers to..." or "This issue means attackers can...".
Explain what it is and why it is dangerous in plain language anyone can understand.
No technical jargon. No markdown. No bullet points. Plain sentences only.

---FIX---

PART 2 (Developer Fix — 1 to 2 sentences):
Give a specific, concrete fix for a developer. Name the exact function, method, or approach to use.
"""
        try:
            response = model.generate_content(prompt)
            text = response.text
            parts = text.split('---FIX---')
            if len(parts) == 2:
                return parts[0].strip(), parts[1].strip()
            return text.strip(), _FALLBACKS.get(vuln_type, _DEFAULT_FALLBACK)[1]
        except Exception as e:
            print(f"⚠️  [AI Engine] Gemini API call failed: {e}")
            # Fall through to built-in fallback

    # ── Offline fallback ──────────────────────────────────────────────────────
    fallback = _FALLBACKS.get(vuln_type, _DEFAULT_FALLBACK)
    explanation = (
        f"{fallback[0]}\n\n"
        f"[Detected in: {endpoint}]"
    )
    return explanation, fallback[1]


def generate_resolution_summary(vuln_type, endpoint):
    """
    Generates a professional report for the client explaining how a fix has secured their system.
    """
    if _GEMINI_AVAILABLE and model:
        prompt = f"""You are a cybersecurity consultant writing a report to a non-technical client.
Tell them that their "{vuln_type}" vulnerability at the "{endpoint}" endpoint has been successfully patched and verified.
Write 2 short, reassuring sentences.
Explain how this fix protects their business/data.
Use professional, confident language. No jargon. No markdown.
"""
        try:
            response = model.generate_content(prompt)
            return response.text.strip()
        except Exception:
            pass

    # Offline fallback
    return (
        f"The {vuln_type} vulnerability at {endpoint} has been successfully mitigated. "
        "A secure code patch was pushed and verified, ensuring that attackers can no longer "
        "exploit this entry point to access your data."
    )
