"""
Evrmore Authentication
======================

A secure, blockchain-based authentication system that leverages Evrmore
wallet signatures for authentication and session management.

This package provides tools to implement user authentication using
Evrmore blockchain wallet signatures in a secure and atomic way.

Copyright © 2023 Manticore Technologies - https://manticore.technology
"""

__version__ = "0.1.0"
__author__ = "Manticore Technologies"
__email__ = "dev@manticore.technology"

from .auth import EvrmoreAuth, UserSession
from .dependencies import get_current_user
from .models import User, Challenge, Session
from .exceptions import (
    AuthenticationError,
    ChallengeExpiredError,
    InvalidSignatureError,
    UserNotFoundError
)

__all__ = [
    "EvrmoreAuth",
    "UserSession",
    "get_current_user",
    "User",
    "Challenge",
    "Session",
    "AuthenticationError",
    "ChallengeExpiredError",
    "InvalidSignatureError",
    "UserNotFoundError"
] 