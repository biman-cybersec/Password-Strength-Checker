from flask import Flask, abort, jsonify, request, send_from_directory

from password_checker import check_password

app = Flask(__name__)

# Only these files are served, so password_checker.py, passwords.txt
# and this file are never exposed to the browser.
WEB_FILES = {"style.css", "script.js", "common-passwords.js", "wordlist.js", 
             "extras.js", "sw.js", "manifest.webmanifest", "icon-192.png", "icon-512.png"}
MAX_BULK = 100_000


@app.get("/")
def home():
    return send_from_directory(".", "index.html")


@app.get("/<name>")
def web_file(name):
    if name not in WEB_FILES:
        abort(404)
    return send_from_directory(".", name)


@app.post("/api/check")
def api_check():
    """Check one password. Body: {"password": "..."}"""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify(error="password must be text"), 400
    return jsonify(check_password(password))


@app.post("/api/bulk")
def api_bulk():
    """Check many passwords. Body: {"passwords": ["...", "..."]}"""
    data = request.get_json(silent=True) or {}
    passwords = data.get("passwords", [])
    if not isinstance(passwords, list) or not all(isinstance(p, str) for p in passwords):
        return jsonify(error="passwords must be a list of text"), 400
    if len(passwords) > MAX_BULK:
        return jsonify(error=f"too many passwords (max {MAX_BULK})"), 413

    results = []
    for pw in passwords:
        r = check_password(pw)
        results.append({"password": pw, "score": r["score"], "label": r["label"]})
    return jsonify(results=results)


if __name__ == "__main__":
    app.run(debug=True)