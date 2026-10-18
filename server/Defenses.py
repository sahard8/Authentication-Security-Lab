import json
import time
import pyotp
import uuid


GROUPSEED = "14320970"
# -----------------------------------------------------------------------------
# TOTP
# -----------------------------------------------------------------------------  

def generate_totp_secret():
    """Generate a random TOTP secret."""
    return pyotp.random_base32()

def generate_totp_code(secret, timestamp= None):
    """Generate a TOTP code for the given secret at a specific time (or current time)."""
    interval_time = 30  # Time step in seconds
    totp = pyotp.TOTP(secret, interval=interval_time)
    if timestamp is None:
        timestamp = int(time.time())
    return totp.at(int(timestamp))
    
def verify_totp_code(secret, code, timestamp= None):
    """
    Verify a TOTP code using a small time window to tolerate clock drift.
    Returns (is_valid, matched_step), where matched_step indicates time offset.
    """
    interval_time = 30  # Time step in seconds
    window = 1    # Allowable time steps for verification
    if timestamp is None:
        timestamp = int(time.time())
    else :
        timestamp = int(timestamp)
    totp = pyotp.TOTP(secret, interval=interval_time)

    # Check current window and neighbors
    for step in range(-window, window + 1):
        time_to_check = timestamp + (step * interval_time)
        if totp.at(time_to_check) == code:
            return True, step
    return False, None


# -----------------------------------------------------------------------------
# captcha
# -----------------------------------------------------------------------------

def generate_token():
    return str(uuid.uuid4().hex)

def verify_token(token, stored_token):
    if token == stored_token:
        return True
    return False


