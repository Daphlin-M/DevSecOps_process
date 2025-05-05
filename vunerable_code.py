"""
Vulnerable Python code example containing 15 common vulnerabilities for scanning and learning purposes.
"""

import os
import sqlite3
import pickle
import subprocess
from flask import Flask, request, render_template_string, session

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Vulnerability: Hardcoded secret key

# 1. Code Injection - Using eval() on user input (dangerous)
def code_injection(user_input):
    return eval(user_input)  # Vulnerable: eval on untrusted input

# 2. SQL Injection - Unsafe query construction with string formatting
def sql_injection(user_id):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER, name TEXT)')
    cursor.execute("INSERT INTO users VALUES (1, 'Alice')")
    query = "SELECT name FROM users WHERE id = '%s'" % user_id  # Vulnerable concat
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    else:
        return None

# 3. Command Injection - Passing unsanitized input to shell command
def command_injection(cmd):
    os.system(cmd)  # Vulnerable: command injection

# 4. Insecure Deserialization - Using pickle.loads on untrusted data
def insecure_deserialization(data):
    return pickle.loads(data)  # Vulnerable: arbitrary code execution risk

# 5. Cross-Site Scripting (XSS) - Rendering unsanitized input in HTML
@app.route('/xss')
def xss():
    user_input = request.args.get('input', '')
    html = f"<h1>User input:</h1><p>{user_input}</p>"  # Vulnerable: no escaping
    return render_template_string(html)

# 6. Directory Traversal - File read using user input path
def directory_traversal(filename):
    with open(f"./files/{filename}", "r") as f:  # Vulnerable: no sanitization of filename
        return f.read()

# 7. Open Redirect - Redirecting based on user-controlled URL
@app.route('/redirect')
def open_redirect():
    target = request.args.get('target', 'https://example.com')
    return f'<meta http-equiv="refresh" content="0;url={target}">'  # Vulnerable: open redirect

# 8. Hardcoded Credentials - Storing credentials in source code
DB_PASSWORD = "password123"  # Vulnerable: hardcoded password

# 9. Sensitive Data Exposure - Printing sensitive info
def print_sensitive_info():
    print(f"DB password is: {DB_PASSWORD}")  # Vulnerable: leaks sensitive data

# 10. Weak Cryptographic Usage - Using insecure hashing (MD5)
import hashlib
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # Vulnerable: MD5 is weak

# 11. Improper Error Handling - Exposing stack traces to users
@app.route('/error')
def error():
    1 / 0  # Vulnerable: causes unhandled exception & stack trace leak

# 12. Session Fixation - Not regenerating session on login
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    if username:
        session['user'] = username  # Vulnerable: no session regeneration
        return "Logged in"
    return "Failed"

# 13. Using Insecure Protocol - Hardcoded use of HTTP without TLS
def fetch_data():
    url = "http://example.com/api"  # Vulnerable: No SSL/TLS (https)
    import requests
    r = requests.get(url)
    return r.text

# 14. Ineffective Input Validation - Accepting any input without checks
def ineffective_validation(user_input):
    # Vulnerable: no validation/sanitization on user input
    return f"Received: {user_input}"

# 15. Mass Assignment - Directly assigning user data to object attributes
class User:
    def __init__(self, data):
        for key, value in data.items():
            setattr(self, key, value)  # Vulnerable: allows overwriting attributes

@app.route('/create_user', methods=['POST'])
def create_user():
    user_data = request.json
    user = User(user_data)  # Vulnerable: no validation on fields
    return "User created"

if __name__ == "__main__":
    # Run Flask app for web vulnerabilities
    app.run(debug=True)
