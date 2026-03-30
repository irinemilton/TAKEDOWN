from flask import Blueprint, request, render_template_string, jsonify
import sqlite3
import os

demo_bp = Blueprint('demo', __name__)

# Very simple vulnerable in-memory sqlite for demo target
target_db = sqlite3.connect(':memory:', check_same_thread=False)
target_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
target_db.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecret')")
target_db.execute("INSERT INTO users (username, password) VALUES ('user', 'password')")
target_db.commit()

# Simulating a state flag to enable auto-fix
FIX_APPLIED = False

@demo_bp.route('/')
def index():
    return """
    <html>
        <body>
            <h1>Test Corp App</h1>
            <form action="/target/search" method="GET">
                <input type="text" name="q" placeholder="Search...">
                <button type="submit">Search</button>
            </form>
            <form action="/target/login" method="POST">
                <input type="text" name="user" placeholder="Username">
                <input type="password" name="pass" placeholder="Password">
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """

@demo_bp.route('/search', methods=['GET'])
def vulnerable_search():
    query = request.args.get('q', '')
    
    if FIX_APPLIED:
        # Secure query (parameterized)
        cursor = target_db.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (query,))
        results = cursor.fetchall()
        
        # Secure response (escape HTML)
        from markupsafe import escape
        return f"<h3>Search Results for: {escape(query)}</h3> <p>Found: {results}</p>"
    else:
        # Vulnerable query (SQLi)
        try:
            cursor = target_db.cursor()
            # Vulnerable to SQL Injection
            cursor.execute(f"SELECT username FROM users WHERE username = '{query}'")
            results = cursor.fetchall()
        except sqlite3.Error as e:
            results = [f"SQL Error: {e}"] # Classic blind/error SQLi leak
        
        # Vulnerable response (XSS)
        return render_template_string(f"<h3>Search Results for: {query}</h3> <p>Found: {results}</p>")

@demo_bp.route('/apply-fix')
def apply_fix():
    global FIX_APPLIED
    FIX_APPLIED = True
    return jsonify({"status": "patched"})

@demo_bp.route('/reset-fix')
def reset_fix():
    global FIX_APPLIED
    FIX_APPLIED = False
    return jsonify({"status": "vulnerable"})

@demo_bp.route('/login', methods=['POST'])
def vulnerable_login():
    # Similar bad login logic for scanner to catch
    username = request.form.get('user', '')
    password = request.form.get('pass', '')

    if FIX_APPLIED:
        cursor = target_db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
        if cursor.fetchone():
            return "Logged in safely! (No cookies though)"
        return "Invalid credentials."
    else:
        try:
            cursor = target_db.cursor()
            # Vulnerable to Auth Bypass bypass
            cursor.execute(f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'")
            if cursor.fetchone():
                return "Logged in! Welcome admin."
            return "Invalid credentials."
        except sqlite3.Error as e:
            return "Database Error"
