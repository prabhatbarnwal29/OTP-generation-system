"""
config.py — Central configuration for the Secure OTP System.
Adjust these values to change security/usability trade-offs.
"""

# --- Storage ---
DB_PATH = "otp_system.db"

# --- OTP generation ---
DEFAULT_OTP_LENGTH = 6          # digits
MIN_OTP_LENGTH = 4
MAX_OTP_LENGTH = 12

# --- Expiration ---
DEFAULT_TTL_SECONDS = 30        # OTP valid for 30 seconds

# --- Rate limiting / brute-force protection ---
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minute lockout

# --- Hashing ---
HASH_ALGORITHM = "sha256"       # used to hash OTPs before storage