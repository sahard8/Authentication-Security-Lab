import json
from datetime import datetime, timedelta
from config_loader import load_config

FILE = "attempts.json"

config = load_config()
account_lockout_enabled = config.get("account_lockout", {}).get("enabled", False)
rate_limiting_enabled = config.get("rate_limiting", {}).get("enabled", False)

PERMA_MAX_ATTEMPTS = config.get("account_lockout", {}).get("max_attempts", 5)
RATE_LIMITING_MAX_ATTEMPTS = config.get("rate_limiting", {}).get("max_attempts", 5)
LOCK_SECONDS = config.get("rate_limiting", {}).get("lockout_duration_seconds", 300)



def initialize_attempts_tracker():
    """Initialize a dictionary to track login attempts for each user."""
    usernames = []
    with open("usernames.txt") as f:
        for line in f:
            usernames.append(line.strip())

    attempts_data = {
        "users":{
            user: {
                "attempts": 0,
                "locked_out_until": None,
                "permanent_lock": False
            } for user in usernames
        }
    }
    with open("attempts.json", "w") as f:
        print("Initializing attempts tracker...")
        json.dump(attempts_data, f, indent=4)

def is_account_locked(username):
    """Check if the account is currently locked.
    Returns True if locked, False otherwise.
    """
    with open(FILE, "r") as attempts_file:
        attempts_json = json.load(attempts_file)

    if username in attempts_json["users"]:
        user = attempts_json["users"][username]
        if user["permanent_lock"]:
            return True
        if user["locked_out_until"]:
            unlock_time = datetime.fromisoformat(user["locked_out_until"])
            #checks if the current time is before the unlock time , for example if unlock time is 12:40pm and current time is 12:30pm then account is still locked
            if datetime.utcnow() < unlock_time or user.get("permanent_lock", False):
                return True
            else:
                # Unlock the account
                user["locked_out_until"] = None
                user["attempts"] = 0
                with open(FILE, "w") as attempts_file:
                    json.dump(attempts_json, attempts_file, indent=4)
                return False
    return False

def record_failed_login(username):
    """Record a failed login attempt for the given username. """
    
    with open(FILE, "r") as attempts_file:
        attempts_json = json.load(attempts_file)
        
    if username not in attempts_json["users"]:
        print(f"Error: Username or Password incorrect.")
        return None # treat as failed login

    user = attempts_json["users"][username]

    # If already locked, do nothing
    if is_account_locked(username):
        print(f"{username} Account for is currently locked.")
        return None

    # Increment attempts
    user["attempts"] += 1


    # Check for lockout conditions and lock if necessary
    if user["attempts"] >= (RATE_LIMITING_MAX_ATTEMPTS-1) and rate_limiting_enabled:
        user["locked_out_until"] = (
            datetime.utcnow() + timedelta(seconds=LOCK_SECONDS)
        ).isoformat()

    if user["attempts"] >= (PERMA_MAX_ATTEMPTS-1) and account_lockout_enabled:
        user["permanent_lock"] = True

    with open(FILE, "w") as attempts_file:
        json.dump(attempts_json, attempts_file, indent=4)

    return None


def record_successful_login(username):
    """Reset the failed login attempts for the given username upon successful login."""
    with open(FILE, "r") as attempts_file:
        attempts_json = json.load(attempts_file)

    if username in attempts_json and attempts_json[username]["locked_out_until"] == None:
        attempts_json[username]["attempts"] = 0

    with open(FILE, "w") as attempts_file:
        json.dump(attempts_json, attempts_file, indent=4)
