#!/usr/bin/env python3
"""
This module provides a database interface for managing user accounts.

The DB class is responsible for creating and interacting with a SQLite database
using SQLAlchemy. It provides methods for adding new users, finding users by
various criteria, and updating user information.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import Base, User


class DB:
    """
    Database interface for managing user accounts.

    Attributes:
        _engine (Engine): SQLAlchemy engine for interacting with the database.
        __session (Session):SQLAlchemy session for current database connection.

    Methods:
        add_user(email, hashed_password): Add a new user to the database.
        find_user_by(**kwargs): Find a user by specified criteria.
        update_user(user_id, **kwargs): Update a user's information.
    """

    def __init__(self) -> None:
        """
        Initialize a new DB instance.

        This method creates a new SQLite database engine, drops any existing
        tables, and creates the necessary tables based on the User model.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """
        Memoized session object for the database connection.

        Returns:
            Session: SQLAlchemy session for the current database connection.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Add a new user to the database.

        Args:
            email (str): The email address of the new user.
            hashed_password (str): The hashed password of the new user.

        Returns:
            User: The newly created User instance.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Find a user by specified criteria.

        Args:
            **kwargs: The criteria for filtering the user search.

        Returns:
            User: The User instance matching the specified criteria.

        Raises:
            NoResultFound: If no user is found matching the criteria.
            InvalidRequestError: If the query is invalid.
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            raise
        except InvalidRequestError:
            raise
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update a user's information.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: The key-value pairs representing the fields to update.

        Raises:
            ValueError:On attempt to update a non-existent attribute.
        """
        user = self.find_user_by(id=user_id)
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
            else:
                raise ValueError
        self._session.commit()
