"""
MAIN SERVER APPLICATION FOR AUTHENTICATION SYSTEM
"""

from flask import Flask, json, render_template, request, session
from users import db, User, add_to_database_from_json, create_user
from recording_logs import log_login
from hashes import hash_password_sha256, verify_password_argon2, verify_password_bcrypt, apply_pepper
import os
from config_loader import load_config
from Defenses import verify_totp_code, generate_token, verify_token
import time
from server_monitor import get_latency_ms
from attempts import initialize_attempts_tracker, record_failed_login, record_successful_login, is_account_locked

# -----------------------------------------------------------------------------
# Flask application setup
# -----------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# Configure the SQLite database (file: dataset.db)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dataset.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with this Flask app (db is imported from users.py)
db.init_app(app)

# -----------------------------------------------------------------------------
# Flask routes
# -----------------------------------------------------------------------------

@app.route('/')
def home():
    """
    Renders the login page (home page of the authentication server).
    """
    
    return render_template('home.html')


@app.route("/login", methods=["GET","POST"])
def login():
    """
    Handles user login requests from the HTML form.
    Reads username/password, validates them, checks DB,
    performs hashing, and returns result page.
    """
    is_password_correct = False
    start = time.perf_counter()

    # 1. Read the username/password from the HTML form submission
    username = request.form.get("username")
    password = request.form.get("password")

    #  Load configuration settings
    config = load_config()
    totp_is_active = config.get("TOTP", False)
    rate_limiting_enabled = config.get("rate_limiting", {}).get("enabled", True)
    account_lockout_enabled = config.get("account_lockout", {}).get("enabled", True)
    captcha_enabled = config.get("captcha", {}).get("enabled", False)
    pepper_enabled = config.get("pepper_enabled", False)
    pepper_value = config["pepper_value"] if pepper_enabled else None # Get pepper value if enabled
    captcha_attempts = config.get("captcha", {}).get("number_of_failed_attempts", 30)
    user_has_token = config.get("captcha", {}).get("user_has_token", False)
    delay_for_incorrect_token_seconds = config.get("captcha", {}).get("delay_for_incorrect_token_seconds", 10)
    delay_for_correct_token_seconds = config.get("captcha", {}).get("delay_for_correct_token_seconds", 1)


    password = apply_pepper(password, pepper_value)  # Apply pepper to the password if provided

    # 2. Basic validation – make sure both fields were provided
    if not username or not password:
        log_login("unknown","unknown" ,"fail_missing_fields", pepper=pepper_enabled, TOTP = totp_is_active, latency_ms = get_latency_ms(start), 
                    RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
        return render_template("home.html", error="Error: Missing username or password")
                               
    # 3. Fetch the user from the database by username
    user = User.query.filter_by(username=username).first()
    
    # ----------------- ACCOUNT LOCKOUT CHECK -----------------
    if account_lockout_enabled and is_account_locked(username):
        print(f"{username} Account is currently locked, please ask the administrator to unlock it.")
        log_login(username,user.hash_mode if user else "unknown" ,result = "fail_account_locked", pepper=pepper_enabled, TOTP = totp_is_active, latency_ms = get_latency_ms(start), 
                    RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
        return render_template("login.html", error="Error: Account is currently locked, please ask the administrator to unlock it.")
    # ------------------------------------------------------------------------

    # -- Rate Limiting Check ---------------------------------
    if rate_limiting_enabled and is_account_locked(username): 
        print("Account is temporarily locked due to too many login attempts. Please try again later.")
        log_login(username,user.hash_mode if user else "unknown" ,result = "fail_account_locked", pepper=pepper_enabled, TOTP = totp_is_active, latency_ms = get_latency_ms(start), 
                    RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
        return render_template("login.html", error="Error: Account is temporarily locked due to too many login attempts. Please try again later.")

    # -----------------------CAPTCHA---------------------------------
    if captcha_enabled :
        with open("attempts.json", "r") as attempts_file:
            data = json.load(attempts_file)
            user_attempts = data["users"].get(username, {}).get("attempts", 0)
            print(f"User {username} has {user_attempts} failed attempts.")
        if (user_attempts + 1) % captcha_attempts == 0 and user_attempts > 0:
            if user_has_token:
                log_login(username,user.hash_mode if user else "unknown" ,result = "captcha_solved", pepper=pepper_enabled, TOTP = totp_is_active, CAPTCHA=True, latency_ms = get_latency_ms(start), 
                            RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
                time.sleep(delay_for_correct_token_seconds)  # Shorter delay for correct token
            elif not user_has_token:
                log_login(username,user.hash_mode if user else "unknown" ,result = "failed_to_complete_CAPTCHA", pepper=pepper_enabled, TOTP = totp_is_active, CAPTCHA=True, latency_ms = get_latency_ms(start), 
                            RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
                time.sleep(delay_for_incorrect_token_seconds)  # Longer delay for incorrect token
    # --------------------------------------------------------

    # 4. Verify the password based on the user's hash mode
    if user is not None:                    
        if user.hash_mode == "sha256":
            is_password_correct = (hash_password_sha256(password, user.salt) == user.password_hash) # Verify password for SHA256
        elif user.hash_mode == "bcrypt":
            is_password_correct = verify_password_bcrypt(password, user.password_hash) # Verify password for Bcrypt
        elif user.hash_mode == "Argon2":
            is_password_correct = verify_password_argon2(password, user.password_hash) # Verify password for Argon2
        else:
            log_login(username,user.hash_mode ,"fail_unsupported_hash_mode", pepper=pepper_enabled, TOTP = totp_is_active, latency_ms = get_latency_ms(start),
                        RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
            return render_template("home.html", error="Error: Unsupported hash mode")
                               
    # 5. check if login is successful
    
    
    if is_password_correct and user is not None: # if Successful login
        if totp_is_active and user.totp_secret is not None:
            session['pending_username'] = username  # Store username in session for TOTP verification
            log_login(username,user.hash_mode ,"first password is correct, pending_TOTP", pepper=pepper_enabled, TOTP = True, latency_ms = get_latency_ms(start), 
                        RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
            return render_template("totp.html", message="Please enter your authentication code")
        else:
            record_successful_login(username)   
            log_login(username,user.hash_mode ,"success", pepper=pepper_enabled, latency_ms = get_latency_ms(start), 
                        RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
            return render_template("result.html", message="Login successful!")
            
                            
    else:  # Username or password is incorrect
        record_failed_login(username)
        log_login(username,user.hash_mode if user else "unknown" ,"fail", pepper=pepper_enabled, TOTP = totp_is_active, latency_ms = get_latency_ms(start), 
                    RateLimit= rate_limiting_enabled, AccountLock = account_lockout_enabled)
        return render_template("home.html", error="Error: Wrong username or password")
        

@app.route("/login_totp", methods=["POST"])
def login_totp():
    """ Handles TOTP verification after the initial password check."""

    start = time.perf_counter()
    interval_time = 30  # Time step in seconds
    pending_username = session.get('pending_username')
    if not pending_username:
        log_login("unknown","unknown" ,result="fail_no_pending_username", TOTP = True, latency_ms = get_latency_ms(start))
        return render_template("home.html", error="Error: Please login first")
        
    user = User.query.filter_by(username=pending_username).first()
    if user is None or user.totp_secret is None:
        session.pop('pending_username', None)  # Clear pending username from session
        log_login(pending_username,user.hash_mode if user else "unknown" ,result="fail_no_totp_configured", TOTP = True, latency_ms = get_latency_ms(start))
        return render_template("home.html", error="Error: TOTP not configured for this user")
        
    totp_code = request.form.get("totp_code")
    if not totp_code:
        log_login(user.username,user.hash_mode ,result="fail_missing_totp_code", TOTP = True, latency_ms = get_latency_ms(start))
        return render_template("totp.html", error="Error: Missing authentication code")
        
    is_valid, step = verify_totp_code(user.totp_secret, totp_code)
    if is_valid: 
        # TOTP code is valid
        session.pop('pending_username', None)  # Clear pending username from session
        offset_seconds = step * interval_time
        log_login(user.username,user.hash_mode ,result=f"success_TOTP_offset_{offset_seconds}s", TOTP = True, latency_ms = get_latency_ms(start))
        return render_template("result.html", message="Login successful!")
    else: 
        # TOTP code is invalid
        log_login(user.username,user.hash_mode ,result="fail_TOTP", TOTP = True, latency_ms = get_latency_ms(start))
        return render_template("totp.html", error="Error: Invalid authentication code")
    

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handles user registration. 
    Allows new users to create an account
    """

    # -------- GET: render registration form --------
    if request.method == "GET":
        return render_template("register.html")

    # -------- POST: handle registration submission --------
    config = load_config()
    user_hash_mode = config.get("hash_mode", "sha256")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    pepper_enabled = config.get("pepper_enabled", False)
    pepper_value = config["pepper_value"] if pepper_enabled else None # Get pepper value if enabled

    try: # Create the new user and add to the database
        create_user(
            username=username,
            plain_password=password,
            strength=None,
            hash_mode=user_hash_mode,
            pepper=pepper_value
        )
        db.session.commit()
        log_login(username,user_hash_mode ,"registration_success", pepper=pepper_enabled, latency_ms = None)
    except Exception:
        db.session.rollback()
        return render_template(
            "register.html",
            error="Registration failed (username may already exist or be invalid)"
        )

    try: # Add the new username to usernames.txt for attack simulations
        with open("usernames.txt", "a", encoding="utf-8") as f:
            f.write(username + "\n")
    except Exception:
        return render_template(
            "result.html",
            message="Registration successful, but usernames file was not updated"
        )

    return render_template(
        "result.html",
        message="Registration successful!"
    )


# ------------------------------------------------------------------------------
# Application entry point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # All database operations must run inside an application context.
    with app.app_context():

        db.drop_all() #removes all tables 
        db.create_all() # Ensure all tables exist
        
        logs_file_path = os.path.join("logs","login_logs.jsonl")
        if os.path.exists(logs_file_path):
            os.remove(logs_file_path)
        else:
            print("Logs file wasn't found\n") #deletes the log file if it exists

        # Load configuration
        config = load_config()
        pepper_value = config["pepper_value"] if config.get("pepper_enabled", False) else None # Get pepper value if enabled
        # Get user preferred hash mode from config
        user_hash_mode = config.get("hash_mode", "sha256")
        print(f"Using hash mode from config: {user_hash_mode}")


        # Seed the database from users.json ONLY if the users table is empty
        if User.query.first() is None:
            print("Loading from users.json...")
            add_to_database_from_json(hash_mode_choice = user_hash_mode, pepper=pepper_value)
        else:
            print("Users already exist. Skipping seeding.")
        
        # Write all usernames from the database to usernames.txt for attack simulations
        if os.path.exists("usernames.txt"):
            os.remove("usernames.txt")
        else:
            print("The file usernames.txt does not exist") 
        
        with open("usernames.txt", "w") as usernames_file:
            users = User.query.all()
            print("Writing usernames to usernames.txt...")
            for u in users:
                usernames_file.write(u.username + "\n")
        if os.path.exists("attempts.json"):
            os.remove("attempts.json")
        else:
            print("The file attempts.json does not exist")

        initialize_attempts_tracker()

    # Start the Flask development server
    app.run(debug=True, use_reloader=False)