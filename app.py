"""app.py - Flask routes only. URL analysis lives in analyzer.py, SQL in database.py."""
import os

from flask import Flask, jsonify, render_template, request

import analyzer
import database

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DATABASE"] = db_path or os.environ.get(
        "LINKSHIELD_DB", os.path.join(BASE_DIR, "linkshield.db"))
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024  # reject request bodies over 8 KB
    database.init_db(app.config["DATABASE"])

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
        return resp

    def error(message, status):
        return jsonify({"ok": False, "error": message}), status

    # ---- Pages ----
    @app.get("/")
    def home():
        return render_template("index.html", rules=analyzer.RULES,
                               medium=analyzer.MEDIUM_THRESHOLD, high=analyzer.HIGH_THRESHOLD)

    @app.get("/history")
    def history_page():
        return render_template("history.html")

    # ---- API ----
    @app.post("/api/scan")
    def scan():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error('Send JSON like {"url": "https://example.com"}.', 400)
        try:
            result = analyzer.analyze_url(data.get("url"))  # string analysis only, no network
        except analyzer.ValidationError as exc:
            return error(str(exc), 400)
        scan_id, stamp = database.save_scan(app.config["DATABASE"], result)
        return jsonify({"ok": True, "scan_id": scan_id, "scanned_at": stamp, "result": result})

    @app.get("/api/history")
    def history():
        try:
            limit = max(1, min(int(request.args.get("limit", 20)), 100))
        except ValueError:
            return error("limit must be a number.", 400)
        return jsonify({"ok": True, "scans": database.get_recent(app.config["DATABASE"], limit)})

    @app.get("/api/history/<int:scan_id>")
    def history_item(scan_id):
        scan_row = database.get_scan(app.config["DATABASE"], scan_id)
        if scan_row is None:
            return error("Scan not found.", 404)
        return jsonify({"ok": True, "scan": scan_row})

    @app.delete("/api/history")
    def clear():
        deleted = database.clear_history(app.config["DATABASE"])
        return jsonify({"ok": True, "deleted": deleted})

    # ---- Errors (JSON for API paths) ----
    @app.errorhandler(413)
    def too_large(_):
        return error("Request is too large.", 413)

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api"):
            return error("Endpoint not found.", 404)
        return render_template("index.html", rules=analyzer.RULES,
                               medium=analyzer.MEDIUM_THRESHOLD, high=analyzer.HIGH_THRESHOLD), 404

    @app.errorhandler(405)
    def bad_method(_):
        return error("Method not allowed.", 405)

    @app.errorhandler(500)
    def server_error(_):
        return error("Something went wrong on the server.", 500)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
