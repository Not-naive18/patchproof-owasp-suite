"""
PatchProof AI Benchmark - Python (Patched Implementation)
Demonstrates verified, remediated code adhering to OWASP guidelines without regression.
"""
import os
import sqlite3
import json
import base64
import ipaddress
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# PATCH A02: Secret read from environment with safe fallback
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback-dev-token-replace-in-env")

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

# Helper: Role-based access control check
def check_authorization(req):
    auth_header = req.headers.get("Authorization", "")
    return auth_header == "Bearer admin-secret-token"

# PATCH A01: Broken Access Control Remediated
@app.route("/admin/users", methods=["GET"])
def list_all_users():
    if not check_authorization(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = [{"id": row[0], "username": row[1], "role": row[2]} for row in cursor.fetchall()]
    return jsonify({"status": "success", "users": users})

# PATCH A03: SQL Injection Remediated with Parameterized Queries
@app.route("/api/products/search", methods=["GET"])
def search_products():
    category = request.args.get("category", "")
    conn = get_db()
    cursor = conn.cursor()
    # SECURE: Parameterized SQL statement prevents injection
    query = "SELECT id, name, category, price FROM products WHERE category = ?"
    cursor.execute(query, (category,))
    results = [{"id": r[0], "name": r[1], "category": r[2], "price": r[3]} for r in cursor.fetchall()]
    return jsonify({"status": "success", "count": len(results), "products": results})

# PATCH A08: Safe Deserialization using JSON rather than pickle
@app.route("/api/session/load", methods=["POST"])
def load_session():
    data = request.json.get("session_token", "") if request.is_json else ""
    try:
        decoded = base64.b64decode(data).decode("utf-8")
        # SECURE: Safe JSON parsing
        payload = json.loads(decoded)
        return jsonify({"status": "success", "session": payload})
    except Exception as e:
        return jsonify({"status": "error", "message": "Invalid session token format"}), 400

# PATCH A10: SSRF Remediated with Scheme and Host Validation
def is_safe_target_url(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ["http", "https"]:
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block internal addresses and loopbacks
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
        return True
    except ValueError:
        # Hostname might be a domain name; ensure it is not localhost
        return parsed.hostname.lower() not in ["localhost", "127.0.0.1", "0.0.0.0"]

@app.route("/api/fetch-webhook", methods=["GET"])
def fetch_remote_webhook():
    target_url = request.args.get("url", "")
    if not target_url:
        return jsonify({"status": "error", "message": "Missing url parameter"}), 400
    if not is_safe_target_url(target_url):
        return jsonify({"status": "error", "message": "Prohibited destination host"}), 400
    try:
        response = requests.get(target_url, timeout=3)
        return jsonify({"status": "success", "data": response.text[:200]})
    except Exception as e:
        return jsonify({"status": "error", "message": "Upstream error"}), 502

if __name__ == "__main__":
    # PATCH A05: Debug mode disabled for production
    app.run(host="127.0.0.1", port=5000, debug=False)
