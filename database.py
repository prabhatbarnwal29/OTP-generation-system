"""
database.py — SQLite persistence layer for the Secure OTP System.
Tables:
    otp_store  : hashed OTP records (used flag for replay protection)
    auth_logs  : audit trail of every verification attempt
    rate_limit : brute-force lockout state per user
"""
import sqlite3
import time
from contextlib import contextmanager

from config import DB_PATH


# ------------------------------------------------------------------
# Connection & schema
# ------------------------------------------------------------------
@contextmanager
def get_conn():
    """Context-managed SQLite connection (auto commit/rollback/close)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they do not exist."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS otp_store (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    TEXT    NOT NULL,
                otp_hash   TEXT    NOT NULL,
                created_at REAL    NOT NULL,
                expires_at REAL    NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_otp_user ON otp_store(user_id);

            CREATE TABLE IF NOT EXISTS auth_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   TEXT,
                timestamp REAL NOT NULL,
                result    TEXT NOT NULL,
                detail    TEXT
            );

            CREATE TABLE IF NOT EXISTS rate_limit (
                user_id      TEXT PRIMARY KEY,
                fail_count   INTEGER NOT NULL DEFAULT 0,
                locked_until REAL    NOT NULL DEFAULT 0
            );
        """)


# ------------------------------------------------------------------
# OTP store operations
# ------------------------------------------------------------------
def insert_otp(user_id: str, otp_hash: str, created_at: float, expires_at: float):
    """Insert a new OTP record, invalidating any previous unused OTPs for the user."""
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM otp_store WHERE user_id = ? AND used = 0", (user_id,)
        )
        conn.execute(
            "INSERT INTO otp_store (user_id, otp_hash, created_at, expires_at, used) "
            "VALUES (?, ?, ?, ?, 0)",
            (user_id, otp_hash, created_at, expires_at),
        )


def get_latest_otp(user_id: str):
    """Return the most recent OTP record for a user, or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM otp_store WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def mark_otp_used(otp_id: int):
    """Flag an OTP as consumed (prevents replay)."""
    with get_conn() as conn:
        conn.execute("UPDATE otp_store SET used = 1 WHERE id = ?", (otp_id,))


# ------------------------------------------------------------------
# Attempt logging
# ------------------------------------------------------------------
def log_attempt(user_id: str, result: str, detail: str | None = None):
    """Append one row to auth_logs."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO auth_logs (user_id, timestamp, result, detail) "
            "VALUES (?, ?, ?, ?)",
            (user_id, time.time(), result, detail),
        )


def fetch_logs(user_id: str | None = None):
    """Return all (or a user's) auth log rows as a list of dicts."""
    with get_conn() as conn:
        if user_id:
            rows = conn.execute(
                "SELECT * FROM auth_logs WHERE user_id = ? ORDER BY id", (user_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM auth_logs ORDER BY id").fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------
# Rate limiting
# ------------------------------------------------------------------
def is_rate_limited(user_id: str) -> bool:
    """True if the user is currently locked out."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT locked_until FROM rate_limit WHERE user_id = ?", (user_id,)
        ).fetchone()
        return bool(row and row["locked_until"] > time.time())


def increment_fail_count(user_id: str, max_fails: int, lock_duration: float):
    """Increment failure counter; lock the user once max_fails is reached."""
    now = time.time()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM rate_limit WHERE user_id = ?", (user_id,)
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO rate_limit (user_id, fail_count, locked_until) "
                "VALUES (?, ?, ?)",
                (user_id, 1, 0),
            )
            return

        # If a previous lock has expired, start a fresh count
        if row["locked_until"] > 0 and now >= row["locked_until"]:
            new_count, locked = 1, 0
        else:
            new_count = row["fail_count"] + 1
            locked = (
                now + lock_duration
                if new_count >= max_fails
                else row["locked_until"]
            )

        conn.execute(
            "UPDATE rate_limit SET fail_count = ?, locked_until = ? WHERE user_id = ?",
            (new_count, locked, user_id),
        )


def reset_fail_count(user_id: str):
    """Clear failure counter (called after a successful verification)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM rate_limit WHERE user_id = ?", (user_id,))