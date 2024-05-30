#!/usr/bin/env python3
"""
This script provides functions to hash passwords and validate
them using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

   Args:
        password (str): The plaintext password to hash.

    Returns:
        bytes: The hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password using bcrypt.

    Args:
        hashed_password (bytes): The hashed password to validate against.
        password (str): The plaintext password to validate.

    Returns:
        bool: True if the password matches the hashed password,
        False otherwise.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
