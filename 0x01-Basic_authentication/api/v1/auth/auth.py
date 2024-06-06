#!/usr/bin/env python3
"""This module defines the Auth class for handling authentication in Flask applications."""

from typing import List, TypeVar
from flask import request

class Auth:
    """The Auth class provides methods for handling authentication in Flask applications."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if authentication is required for a given path.

        Args:
            path (str): The path to be checked for authentication requirement.
            excluded_paths (List[str]): A list of paths exempt from authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        # If path or excluded_paths is None or empty, authentication is required
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        
        # Append '/' to path if it doesn't already end with it
        if path[-1] != "/":
            path += "/"

        # Check if path is in excluded_paths
        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """Retrieve the Authorization header value from the request.

        Args:
            request (flask.Request, optional): The request object. Defaults to None.

        Returns:
            str: The value of the Authorization header, or None if not present.
        """
        if request is None:
            return None
        
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):
        """Retrieve information about the current user.

        Args:
            request (flask.Request, optional): The request object. Defaults to None.

        Returns:
            TypeVar("User"): Information about the current user, or None if not available.
        """
        return None
