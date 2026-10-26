"""
otp_manager.py — Core OTP generation & verification logic.

Security properties implemented here:
  * OTPs are generated with `secrets` (CSPRNG from OS entropy).
  * OTPs are hashed before storage (SHA-256).
  * Verification compares hashes in constant time (hmac.compare_digest).
  * Each successful verification marks the OTP `used` → replay blocked.
  * Repeated failures trigger a lockout → brute-force blocked.
"""
import hashlib
import hmac
import secrets
import string
import time

import config
import database as db

_DIGITS = string.digits


# ------------------------------------------------------------------
# Low-level primitives
# ------------------------------------------------------------------
def generate_otp(length: int = config.DEFAULT_OTP_LENGTH) -> str:
    """Generate a cryptographically secure numeric OTP."""
    if not (config.MIN_OTP_LENGTH <= length <= config.MAX_OTP_LENGTH):
        raise ValueError(
            f"OTP length must be in [{config.MIN_OTP_LENGTH}, {config.MAX_OTP_LENGTH}]"
        )
    return "".join(secrets.choice(_DIGITS) for _ in range(length))


def hash_otp(otp: str) -> str:
    """Return the hex digest of the OTP."""
    return hashlib.new(config.HASH_ALGORITHM, otp.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------
# High-level API
# ------------------------------------------------------------------
def create_otp(
    user_id: str,
    length: int = config.DEFAULT_OTP_LENGTH,
    ttl: int = config.DEFAULT_TTL_SECONDS,
) -> str:
    """Generate, hash, and persist an OTP. Returns the plaintext OTP
    (for the demo — in a real app this would be sent to the user)."""
    otp = generate_otp(length)
    now = time.time()
    db.insert_otp(user_id, hash_otp(otp), now, now + ttl)
    return otp


def verify_otp(user_id: str, input_otp: str) -> str:
    """Verify an OTP. Returns one of:
         SUCCESS | INVALID | EXPIRED | REUSED | RATE_LIMITED
    """
    # 1. Rate limit check (do it first so a locked user can never guess)
    if db.is_rate_limited(user_id):
        db.log_attempt(user_id, "RATE_LIMITED")
        return "RATE_LIMITED"

    # 2. Fetch the latest OTP record for this user
    record = db.get_latest_otp(user_id)
    if record is None:
        db.log_attempt(user_id, "INVALID", "no active OTP")
        return "INVALID"

    # 3. Replay protection
    if record["used"]:
        db.log_attempt(user_id, "REUSED")
        return "REUSED"

    # 4. Expiry
    if time.time() > record["expires_at"]:
        db.log_attempt(user_id, "EXPIRED")
        return "EXPIRED"

    # 5. Constant-time hash comparison
    if not hmac.compare_digest(hash_otp(input_otp), record["otp_hash"]):
        db.increment_fail_count(
            user_id,
            config.MAX_FAILED_ATTEMPTS,
            config.LOCKOUT_DURATION_SECONDS,
        )
        db.log_attempt(user_id, "INVALID", "hash mismatch")
        return "INVALID"

    # 6. Success — consume the OTP and reset counters
    db.mark_otp_used(record["id"])
    db.reset_fail_count(user_id)
    db.log_attempt(user_id, "SUCCESS")
    return "SUCCESS"


# ------------------------------------------------------------------
# Optional PyOTP helpers (standard TOTP — for interop with
# Google Authenticator / Authy etc.)
# ------------------------------------------------------------------
def totp_secret() -> str:
    import pyotp
    return pyotp.random_base32()


def totp_now(secret: str, interval: int = 30) -> str:
    import pyotp
    return pyotp.TOTP(secret, interval=interval).now()


def totp_verify(secret: str, code: str, interval: int = 30) -> bool:
    import pyotp
    return pyotp.TOTP(secret, interval=interval).verify(code, valid_window=0)