#!/usr/bin/env python3
"""
This module defines the User model for the application's database.
The User model represents a user account and stores relevant information
such as email, hashed password, session ID, and password reset token.
"""
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """
    User model representing a user account in the application.

    Attributes:
        __tablename__ (str): The name of the database table for the User model.
        id (Column): The unique identifier for the user.
        email (Column): The email address associated with the user account.
        hashed_password (Column): The securely hashed password for the user.
        session_id (Column): The session identifier for an authenticated user.
        reset_token (Column): The token used for password reset functionality.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        """
        Returns a string representation of the User object.

        Returns:
            str: A string representation of the User object.
        """
        return f"User(id={self.id}, email='{self.email}')"
