"""
main.py — Demo entry point for the Secure OTP System.

Run:  python main.py
"""
import time

import config
import database as db
from otp_manager import create_otp, verify_otp


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def section(title: str):
    print("\n" + "=" * 62)
    print(f" {title}")
    print("=" * 62)


def _reset(uid: str):
    with db.get_conn() as conn:
        conn.execute("DELETE FROM otp_store  WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM auth_logs  WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM rate_limit WHERE user_id = ?", (uid,))


# ------------------------------------------------------------------
# Scenarios
# ------------------------------------------------------------------
def demo_basic():
    section("Scenario 1: Generate + Verify")
    uid = "alice"
    _reset(uid)
    otp = create_otp(uid, length=6, ttl=30)
    print(f"  Generated OTP : {otp}")
    print(f"  Verify correct: {verify_otp(uid, otp)}")


def demo_replay():
    section("Scenario 2: Replay Attack")
    uid = "bob"
    _reset(uid)
    otp = create_otp(uid, length=6, ttl=30)
    print(f"  OTP           : {otp}")
    print(f"  First verify  : {verify_otp(uid, otp)}")
    print(f"  Replay verify : {verify_otp(uid, otp)}   <-- must be REUSED")


def demo_wrong():
    section("Scenario 3: Wrong OTP")
    uid = "carol"
    _reset(uid)
    otp = create_otp(uid, length=6, ttl=30)
    wrong = "000000" if otp != "000000" else "111111"
    print(f"  Real OTP      : {otp}")
    print(f"  Attempt       : {wrong}")
    print(f"  Result        : {verify_otp(uid, wrong)}")


def demo_expiry():
    section("Scenario 4: Expired OTP")
    uid = "dave"
    _reset(uid)
    otp = create_otp(uid, length=6, ttl=1)
    print(f"  OTP           : {otp}  (TTL = 1s, waiting 1.5s...)")
    time.sleep(1.5)
    print(f"  Verify        : {verify_otp(uid, otp)}   <-- must be EXPIRED")


def demo_brute_force():
    section("Scenario 5: Brute-Force / Rate Limiting")
    uid = "eve"
    _reset(uid)
    otp = create_otp(uid, length=6, ttl=30)
    wrong = "000000" if otp != "000000" else "111111"

    for i in range(config.MAX_FAILED_ATTEMPTS + 1):
        print(f"  Attempt {i + 1:>2}   : {verify_otp(uid, wrong)}")

    print(f"  Correct OTP after lockout : {verify_otp(uid, otp)}   <-- must be RATE_LIMITED")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    db.init_db()

    print("Secure OTP System — Demo")
    print(
        f"Config: length={config.DEFAULT_OTP_LENGTH}, "
        f"TTL={config.DEFAULT_TTL_SECONDS}s, "
        f"max_fails={config.MAX_FAILED_ATTEMPTS}, "
        f"lockout={config.LOCKOUT_DURATION_SECONDS}s"
    )

    demo_basic()
    demo_replay()
    demo_wrong()
    demo_expiry()
    demo_brute_force()

    section("Auth Log (last 20 entries)")
    for log in db.fetch_logs()[-20:]:
        detail = f"  ({log['detail']})" if log["detail"] else ""
        print(f"  [{log['result']:>12}] user={log['user_id']}{detail}")


if __name__ == "__main__":
    main()