"""
app.py — Flask web interface for the Secure OTP System.

Run:  python app.py
Then open:  http://127.0.0.1:5000
"""
from flask import Flask, render_template, request, jsonify

import config
import database as db
from otp_manager import create_otp, verify_otp
from email_service import send_otp_email


app = Flask(__name__)


# ------------------------------------------------------------------
# UI
# ------------------------------------------------------------------
@app.get("/")
def index():
    return render_template(
        "index.html",
        default_length=config.DEFAULT_OTP_LENGTH,
        default_ttl=config.DEFAULT_TTL_SECONDS,
        min_length=config.MIN_OTP_LENGTH,
        max_length=config.MAX_OTP_LENGTH,
        max_fails=config.MAX_FAILED_ATTEMPTS,
        lockout=config.LOCKOUT_DURATION_SECONDS,
    )


# ------------------------------------------------------------------
# API — Generate OTP and email it
# ------------------------------------------------------------------
@app.post("/api/generate")
def api_generate():
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or "").strip()
    email   = (data.get("email") or "").strip()

    if not user_id:
        return jsonify(error="user_id is required"), 400
    if not email or "@" not in email:
        return jsonify(error="A valid email is required"), 400

    try:
        length = int(data.get("length", config.DEFAULT_OTP_LENGTH))
        ttl    = int(data.get("ttl",    config.DEFAULT_TTL_SECONDS))
    except (TypeError, ValueError):
        return jsonify(error="length and ttl must be integers"), 400

    if ttl <= 0:
        return jsonify(error="ttl must be positive"), 400

    try:
        otp = create_otp(user_id, length=length, ttl=ttl)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # --- Send the OTP via email -------------------------------------
    sent = send_otp_email(email, otp, ttl_seconds=ttl)

    if not sent:
        return jsonify(error="OTP generated but email could not be sent. "
                             "Check SMTP settings."), 500

    # Do NOT return the OTP in the JSON response.
    return jsonify(message=f"OTP sent to {email}", length=length, ttl=ttl)


# ------------------------------------------------------------------
# API — Verify OTP
# ------------------------------------------------------------------
@app.post("/api/verify")
def api_verify():
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or "").strip()
    otp     = (data.get("otp") or "").strip()

    if not user_id or not otp:
        return jsonify(error="user_id and otp are required"), 400

    result = verify_otp(user_id, otp)
    return jsonify(result=result)


# ------------------------------------------------------------------
# API — Logs & stats
# ------------------------------------------------------------------
@app.get("/api/logs")
def api_logs():
    user_id = (request.args.get("user_id") or "").strip() or None
    logs = list(reversed(db.fetch_logs(user_id)))[:50]   # newest first, cap 50
    return jsonify(logs=logs)


@app.get("/api/stats")
def api_stats():
    logs = db.fetch_logs()
    counts = {}
    for row in logs:
        counts[row["result"]] = counts.get(row["result"], 0) + 1
    return jsonify(total=len(logs), counts=counts)


# ------------------------------------------------------------------
# Entry point — ALWAYS last in the file
# ------------------------------------------------------------------
if __name__ == "__main__":
    db.init_db()
    print("Starting Secure OTP Web UI → http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)