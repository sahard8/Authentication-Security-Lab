import json
import os
from datetime import datetime


LOG_FILE = os.path.join("logs","login_logs.jsonl")



def log_login(username, hash_mode, result, pepper= False, RateLimit = False, AccountLock = False, CAPTCHA = False, TOTP = False, latency_ms = None):
    """Records and saves logs about a login attempt.

    :param username: The username that was typed in forms.
    :param result: Was the login attempt succeful or not.
    """
    current_time = datetime.now()
    log = {
        "GROUP_SEED" : "14320970",
        "time" : current_time.strftime("%d/%m/%Y %H:%M:%S") + f":{current_time.microsecond // 1000:03d}",
        "username" : username,
        "hash_mode" : hash_mode,
        "result" : result,
        "pepper" : pepper,
        "RateLimit" : RateLimit,
        "AccountLock" : AccountLock,
        "CAPTCHA" : CAPTCHA,
        "TOTP" : TOTP,
        "latency_ms" : latency_ms
        
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")