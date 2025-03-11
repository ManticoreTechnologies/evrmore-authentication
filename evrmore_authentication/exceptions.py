"""Exceptions for Evrmore Authentication.

This module defines custom exceptions used throughout the Evrmore Authentication system.
"""

class AuthenticationError(Exception):
    """Base exception for all authentication-related errors."""
    pass

class ChallengeExpiredError(AuthenticationError):
    """Exception raised when an authentication challenge has expired."""
    
    def __init__(self, challenge_id=None):
        message = f"Authentication challenge has expired"
        if challenge_id:
            message += f" (challenge_id: {challenge_id})"
        super().__init__(message)
        self.challenge_id = challenge_id

class InvalidSignatureError(AuthenticationError):
    """Exception raised when a signature verification fails."""
    
    def __init__(self, evrmore_address=None):
        message = "Invalid signature provided"
        if evrmore_address:
            message += f" for address {evrmore_address}"
        super().__init__(message)
        self.evrmore_address = evrmore_address

class UserNotFoundError(AuthenticationError):
    """Exception raised when a user is not found."""
    
    def __init__(self, identifier=None):
        message = "User not found"
        if identifier:
            message += f" (identifier: {identifier})"
        super().__init__(message)
        self.identifier = identifier

class SessionExpiredError(AuthenticationError):
    """Exception raised when a session has expired."""
    
    def __init__(self, session_id=None):
        message = "Session has expired"
        if session_id:
            message += f" (session_id: {session_id})"
        super().__init__(message)
        self.session_id = session_id

class InvalidTokenError(AuthenticationError):
    """Exception raised when a token is invalid."""
    
    def __init__(self, message="Invalid authentication token"):
        super().__init__(message)

class ChallengeAlreadyUsedError(AuthenticationError):
    """Exception raised when a challenge has already been used."""
    
    def __init__(self, challenge_id=None):
        message = "Challenge has already been used"
        if challenge_id:
            message += f" (challenge_id: {challenge_id})"
        super().__init__(message)
        self.challenge_id = challenge_id

class ConfigurationError(Exception):
    """Exception raised when there is a configuration error."""
    
    def __init__(self, message="Authentication system configuration error"):
        super().__init__(message) 