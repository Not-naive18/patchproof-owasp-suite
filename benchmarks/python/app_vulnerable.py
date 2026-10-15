"""
PatchProof AI Benchmark - Python (Vulnerable Implementation)
Demonstrates OWASP Top 10 patterns before automated patching.
"""
import sqlite3
import pickle
import base64
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# OWASP A02:2021 - Cryptographic Failures / Hardcoded Secret
SECRET_KEY = "SUPER_SECRET_UNENCRYPTED_KEY_12345"
app.config["SECRET_KEY"] = SECRET_KEY

def get_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)")
    cursor.execute("INSERT INTO products VALUES (1, 'Secure Laptop', 'hardware', 1200.00)")
    cursor.execute("INSERT INTO products VALUES (2, 'Encrypted USB', 'hardware', 45.00)")
    cursor.execute("INSERT INTO products VALUES (3, 'Security Book', 'books', 29.99)")
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'alice', 'admin')")
    cursor.execute("INSERT INTO users VALUES (2, 'bob', 'user')")
    conn.commit()
    return conn

# OWASP A01:2021 - Broken Access Control
# Missing authorization check on administrative endpoints
@app.route("/admin/users", methods=["GET"])
def list_all_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = [{"id": row[0], "username": row[1], "role": row[2]} for row in cursor.fetchall()]
    return jsonify({"status": "success", "users": users})

# OWASP A03:2021 - Injection (SQL Injection)
# Direct string formatting into SQL query allows SQLi
@app.route("/api/products/search", methods=["GET"])
def search_products():
    category = request.args.get("category", "")
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: Direct f-string formatting
    query = f"SELECT id, name, category, price FROM products WHERE category = '{category}'"
    cursor.execute(query)
    results = [{"id": r[0], "name": r[1], "category": r[2], "price": r[3]} for r in cursor.fetchall()]
    return jsonify({"status": "success", "count": len(results), "products": results})

# OWASP A08:2021 - Software and Data Integrity Failures
# Unsafe deserialization using pickle
@app.route("/api/session/load", methods=["POST"])
def load_session():
    data = request.json.get("session_token", "")
    try:
        decoded = base64.b64decode(data)
        # VULNERABLE: Arbitrary code execution via pickle deserialization
        payload = pickle.loads(decoded)
        return jsonify({"status": "success", "session": payload})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# OWASP A10:2021 - Server-Side Request Forgery (SSRF)
# Direct fetch from user-supplied URL without destination validation
@app.route("/api/fetch-webhook", methods=["GET"])
def fetch_remote_webhook():
    target_url = request.args.get("url", "")
    if not target_url:
        return jsonify({"status": "error", "message": "Missing url parameter"}), 400
    # VULNERABLE: Direct request to arbitrary external or internal IP/host
    response = requests.get(target_url, timeout=3)
    return jsonify({"status": "success", "data": response.text[:200]})

if __name__ == "__main__":
    # OWASP A05:2021 - Security Misconfiguration (Debug mode in production)
    app.run(host="0.0.0.0", port=5000, debug=True)
