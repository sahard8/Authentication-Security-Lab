import hashlib
import bcrypt
import os
from passlib.hash import argon2
# -----------------------------------------------------------------------------
# sha256
# -----------------------------------------------------------------------------   

def generate_salt():
    """
    Generates a random salt for hashing.
    Returns:
        str: A 32-character hex string representing 16 random bytes.
    """
    return os.urandom(16).hex()


def hash_password_sha256(password, salt):
    """
    Hashes a password using SHA-256 with the provided salt.
    Args:
        password (str): The plain-text password to hash.
        salt (str): The salt to use in hashing.
    Returns:
        str: The resulting SHA-256 hash as a hex string.
    """
    data = (salt + password).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

# -----------------------------------------------------------------------------
# bcrypt
# -----------------------------------------------------------------------------   

def hash_password_bcrypt(password):
    """
    Hashes a password using bcrypt with a cost factor of 12.

    Args:
        password (str): The plain-text password to hash.

    Returns:
        str: The resulting bcrypt hash as a string.
    """
    password_bytes = password.encode("utf-8") # Convert to bytes
    salt = bcrypt.gensalt(rounds=12) # Generate a salt with a cost factor of 12
    hashed_bytes = bcrypt.hashpw(password_bytes, salt) # Hash the password with the salt
    return hashed_bytes.decode("utf-8") # Convert back to string and return


def verify_password_bcrypt(password, stored_hash):
    """
    Verifies a password against a stored bcrypt hash.

    Args:
        password (str): The plain-text password to verify.
        stored_hash (str): The stored bcrypt hash to verify against.

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    password_bytes = password.encode("utf-8") # Convert to bytes
    stored_hash_bytes = stored_hash.encode("utf-8") # Convert stored hash to bytes
    return bcrypt.checkpw(password_bytes, stored_hash_bytes) # Verify the password against the stored hash

# -----------------------------------------------------------------------------
# Argon2
# ----------------------------------------------------------------------------- 

def hash_password_argon2(password):
    """
    Hashes a password using Argon2 with specified parameters.
    parameters: time_cost = 1, memory_cost = 65536, parallelism = 1

    Args:
        password(str) "-" The plain-text password provided by the user.
        
    Returns:
        str: The resulting Argon2 hash as a string.
    """
    return argon2.using(time_cost = 1, memory_cost = 65536, parallelism = 1).hash(password) # Hash the password using Argon2 with specified parameters


def verify_password_argon2(password, stored_hash):
    """
    Verifies a password against a stored Argon2id hash.
    Args:
        password (str): The plain-text password to verify.
        stored_hash (str): The stored Argon2id hash to verify against.
    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    return argon2.verify(password, stored_hash) # Verify the password against the stored hash

# -----------------------------------------------------------------------------
# pepper
# -----------------------------------------------------------------------------

def apply_pepper(password, pepper):
    """
    Applies a pepper to the password by concatenation.
    Args:
        password (str): The plain-text password.
        pepper (str): The pepper value to apply.
    Returns:
        str: The password concatenated with the pepper.
    """
    if pepper is None:
        return password
    return password + pepper