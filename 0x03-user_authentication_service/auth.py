#!/usr/bin/env python3
"""
This module provides an authentication system for managing user accounts.

The Auth class handles user authentication, registration, session management,
password reset, and related operations by interacting with the database through
the DB class.
"""
from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import TypeVar


def _hash_password(password: str) -> bytes:
    """
    Hash a plaintext password using bcrypt.

    Args:
        password (str): The plaintext password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generate a new UUID.

    Returns:
        str: A string representation of the generated UUID.
    """
    return str(uuid.uuid4())


UserT = TypeVar("UserT", bound=User)


class Auth:
    """
    Auth class to interact with the authentication database.

    Attributes:
        _db (DB): The database interface instance.

    Methods:
        valid_login(email, password): Check if credentials are valid.
        register_user(email, password): Register a new user.
        create_session(email): Create a new session for a user.
        get_user_from_session_id(session_id): Get associated with a session ID.
        destroy_session(user_id): Destroy a user's session.
        get_reset_password_token(email): Get a password reset token for a user.
        update_password(reset_token, password): Update a user's password.
    """

    def __init__(self):
        self._db = DB()

    def valid_login(self, email: str, password: str) -> bool:
        """
        Check if the provided email and password are valid.

        Args:
            email (str): The user's email address.
            password (str): The user's password.

        Returns:
            bool: True if the credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode(), user.hashed_password)
        except NoResultFound:
            return False

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user with the provided email and password.

        Args:
            email (str): The user's email address.
            password (str): The user's password.

        Returns:
            User: The newly registered User instance.

        Raises:
            ValueError: If a user with the provided email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            user = self._db.add_user(email, _hash_password(password))
            return user

    def create_session(self, email: str) -> str:
        """
        Create a new session for the user with the provided email.

        Args:
            email (str): The user's email address.

        Returns:
            str: The session ID for the new session,
            or None if the user doesn't exist.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> UserT:
        """
        Get the user associated with the provided session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            User: The User instance associated with the session ID,
                or None if not found.
        """
        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy the session for the user with the provided ID.

        Args:
            user_id (int):ID of the user whose session should be destroyed.
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Get a password reset token for the user with the provided email.

        Args:
            email (str): The user's email address.

        Returns:
            str: The password reset token.

        Raises:
            ValueError: If no user with the provided email exists.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update the password for the user associated with the reset token.

        Args:
            reset_token (str): The password reset token.
            password (str): The new password.

        Raises:
            ValueError: If the reset token or password is None, or if the reset
                token is invalid.
        """
        if reset_token is None or password is None:
            raise ValueError
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password,
                             reset_token=None)
