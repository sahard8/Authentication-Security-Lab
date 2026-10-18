"""
This file defines the User model and functions to create users and to put them into the database.
"""
from flask_sqlalchemy import SQLAlchemy
import hashlib
import json
from hashes import generate_salt, hash_password_argon2, hash_password_sha256, hash_password_bcrypt, apply_pepper

db = SQLAlchemy()

# create User model (table) for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(32))
    hash_mode = db.Column(db.String(20), nullable=False)
    password_strength = db.Column(db.String(10))
    totp_secret = db.Column(db.String(64), nullable=True)


# -----------------------------------------------------------------------------
# Add user to database "dataset.db"
# -----------------------------------------------------------------------------

def create_user(username, plain_password, strength=None, hash_mode="sha256", totp_secret=None, pepper=None):
    """
    Creates a new user with a hashed password and adds it to the current database session.
    """

    # 1. Apply pepper if provided
    plain_password = apply_pepper(plain_password, pepper)

    # 2. Hash the password according to the selected mode
    if hash_mode == "sha256":
        salt = generate_salt()
        password_hash = hash_password_sha256(plain_password, salt)
    elif hash_mode == "bcrypt":
        password_hash = hash_password_bcrypt(plain_password)
        salt = None  # Bcrypt manages its own salt internally
    elif hash_mode == "Argon2":
        password_hash = hash_password_argon2(plain_password)
        salt = None  # Argon2 manages its own salt internally
    else:
        raise ValueError(f"Unsupported hash mode: {hash_mode}")

    # 3. Create the User object
    user = User(
        username = username,
        password_hash = password_hash,
        salt = salt,
        hash_mode = hash_mode,
        password_strength = strength,
        totp_secret = totp_secret
    )

    # 4. Add the user to the current database session
    db.session.add(user)

    return user


def add_to_database_from_json(path="users.json", hash_mode_choice = "sha256", pepper=None):
    """
    Loads users from a JSON file and adds them to the database.
    """

    # 1. Load list of logical users from JSON file
    with open(path, "r", encoding="utf-8") as f:
        users_list = json.load(f)

    # 2. Create each user in the database session - each entry is a user  
    # each user is a dictionary object that contains all the relevant properties of the user. 
    for entry in users_list:
        create_user(
            username = entry["username"],
            plain_password = entry["password"],
            strength = entry["password_strength"],
            hash_mode = hash_mode_choice,
            totp_secret = entry.get("totp_secret"), # Optional TOTP secret, None if not provided
            pepper = pepper
        )

    # 3. Commit all changes to the database
    db.session.commit()
