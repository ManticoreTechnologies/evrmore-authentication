"""
Evrmore Authentication
======================

A lightweight authentication system using Evrmore blockchain signatures.
The package includes built-in Evrmore signature verification without requiring an Evrmore node.

Copyright © 2023-2024 Manticore Technologies - https://manticore.technology
"""

import os
import logging
from logging.handlers import RotatingFileHandler

__version__ = "1.0.0"
__author__ = "Manticore Technologies"
__email__ = "dev@manticore.technology"
__url__ = "https://github.com/manticoretechnologies/evrmore-authentication"
__license__ = "MIT"

# Set up logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, LOG_LEVEL, logging.INFO)

# Configure the root logger
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

# Create package logger
logger = logging.getLogger("evrmore_authentication")
logger.setLevel(log_level)

from .auth import EvrmoreAuth, UserSession
from .models import User, Challenge, Session
# Import OAuth models
from .models import OAuthClient, OAuthAuthorizationCode, OAuthToken
from .crypto import (
    sign_message,
    verify_message,
    generate_key_pair,
    pubkey_to_address,
    wif_to_privkey
)
from .exceptions import (
    AuthenticationError,
    UserNotFoundError,
    ChallengeExpiredError,
    ChallengeAlreadyUsedError,
    InvalidSignatureError,
    InvalidTokenError,
    SessionExpiredError,
    ConfigurationError,
)

# For FastAPI integration
from .dependencies import get_current_user

__all__ = [
    # Core authentication classes
    "EvrmoreAuth",
    "UserSession",
    
    # Database models
    "User",
    "Challenge", 
    "Session",
    
    # OAuth models
    "OAuthClient",
    "OAuthAuthorizationCode",
    "OAuthToken",
    
    # Crypto functions
    "sign_message",
    "verify_message",
    "generate_key_pair",
    "pubkey_to_address",
    "wif_to_privkey",
    
    # Exceptions
    "AuthenticationError",
    "UserNotFoundError",
    "ChallengeExpiredError",
    "ChallengeAlreadyUsedError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "SessionExpiredError",
    "ConfigurationError",
    
    # FastAPI dependencies
    "get_current_user"
]

# API function to run the server
def run_api_main():
    """Entry point for the API server command-line tool."""
    from .api import run_api
    import argparse
    
    parser = argparse.ArgumentParser(description="Evrmore Authentication API Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    
    args = parser.parse_args()
    run_api(host=args.host, port=args.port, reload=args.reload) 