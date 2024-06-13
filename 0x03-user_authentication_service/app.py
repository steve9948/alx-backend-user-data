#!/usr/bin/env python3
"""
This module provides a Flask application for user authentication and
password management. It defines various routes for handling user
registration, login, logout, profile retrieval, and password reset.
"""
from flask import Flask, jsonify, request, make_response
from flask import abort, Response, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> Response:
    """
    Handle user login.

    Retrieves the email and password from the request form data, checks if
    the credentials are valid using the Auth class, and creates a new
    session for the user if the credentials are valid. Returns a JSON
    response with a success message and sets a cookie with the session ID.
    If the credentials are invalid, aborts with a 401 Unauthorized status.

    Returns:
        Response: A Flask Response object with the appropriate JSON data
        and status code.
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if AUTH.valid_login(email, password):
        jsoni = jsonify({"email": email, "message": "logged in"}), 200
        response = make_response(jsoni)
        response.set_cookie("session_id", AUTH.create_session(email))
        return response
    abort(401)


@app.route("/users", methods=["POST"])
def users() -> Response:
    """
    Handle user registration.

    Retrieves the email and password from the request form data, tries to
    register a new user using the Auth class. If successful, returns a JSON
    response with a success message. If the email is already registered,
    returns a JSON response with an error message and a 400 Bad Request
    status code.

    Returns:
        Response: A Flask Response object with the appropriate JSON data
        and status code.
    """
    email = request.form["email"]
    password = request.form["password"]
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/", methods=["GET"])
def welcome() -> Response:
    """
    Render the welcome message.

    Returns a JSON response with a welcome message.

    Returns:
        Response: A Flask Response object with a JSON welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> Response:
    """
    Handle user logout.

    Retrieves the session ID from the request cookies, gets the user
    associated with the session ID using the Auth class. If no user is
    found, aborts with a 403 Forbidden status code. Otherwise, destroys the
    user's session using the Auth class and redirects to the root path.

    Returns:
        Response: A Flask Response object with a redirect to the root path,
        or a 403 Forbidden status code if no user is found.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> Response:
    """
    Retrieve the user's profile.

    Retrieves the session ID from the request cookies, gets the user
    associated with the session ID using the Auth class. If no user is
    found, aborts with a 403 Forbidden status code. Otherwise, returns a
    JSON response with the user's email.

    Returns:
        Response: A Flask Response object with the user's email in JSON
        format and a 200 status code, or a 403 Forbidden status code if no
        user is found.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> Response:
    """
    Request a password reset token.

    Retrieves the email from the request form data, tries to get a password
    reset token using the Auth class. If the email is not found, aborts with
    a 403 Forbidden status code. Otherwise, returns a JSON response with the
    email and the reset token.

    Returns:
        Response: A Flask Response object with the email and reset token in
        JSON format and a 200 status code, or a 403 Forbidden status code if
        the email is not found.
    """
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> Response:
    """
    Update the user's password after receiving a reset token.

    Retrieves the email, reset token, and new password from the request form
    data, tries to update the password using the Auth class. If the reset
    token or password is invalid, aborts with a 403 Forbidden status code.
    Otherwise, returns a JSON response with a success message.

    Returns:
        Response: A Flask Response object with a success message in JSON
        format and a 200 status code, or a 403 Forbidden status code if the
        reset token or password is invalid.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
