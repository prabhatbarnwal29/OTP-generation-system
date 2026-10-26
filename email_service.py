"""
email_service.py — Brevo HTTP API version (uses HTTPS port 443).
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"  # HTTPS, port 443


def send_otp_email(to_email: str, otp_code: str, ttl_seconds: int = 30) -> bool:
    """Send the OTP via Brevo's HTTP API. Returns True on success."""
    if not BREVO_API_KEY:
        print("⚠️ BREVO_API_KEY not configured. Email not sent.")
        return False

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": BREVO_API_KEY,   # Brevo authenticates with this header
    }

    html_content = f"""
    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
        <h2>Your Verification Code</h2>
        <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px;
                    color: #3b82f6; background: #eff6ff; padding: 15px;
                    border-radius: 6px; margin: 20px 0;">
            {otp_code}
        </div>
        <p>This code expires in <b>{ttl_seconds} seconds</b>.</p>
    </div>
    """

    payload = {
        "sender": {"email": FROM_EMAIL, "name": "OTP Service"},
        "to": [{"email": to_email}],
        "subject": "Your Secure OTP Code",
        "htmlContent": html_content,
        "textContent": f"Your verification code is {otp_code}. It expires in {ttl_seconds} seconds.",
    }

    try:
        response = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=15)

        if response.status_code in (200, 201):
            print(f"✅ Email sent via Brevo API to {to_email}")
            return True

        # Log the API's error message for diagnosis
        try:
            err = response.json()
            print(f"❌ Brevo API error {response.status_code}: {err}")
        except Exception:
            print(f"❌ Brevo API error {response.status_code}: {response.text[:200]}")
        return False

    except requests.exceptions.ConnectionError:
        print("❌ Cannot reach api.brevo.com — check your internet connection.")
        return False
    except requests.exceptions.Timeout:
        print("❌ Brevo API request timed out.")
        return False
    except Exception as exc:
        print(f"❌ Failed to send email via Brevo API: {exc}")
        return False