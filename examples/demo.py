#!/usr/bin/env python3
"""
Evrmore Authentication Demo

This script demonstrates the authentication flow with the SQLite backend.
It showcases the challenge generation, signing, authentication, and token verification.

© 2023-2024 Manticore Technologies - manticore.technology
"""

import os
import sys
import time
import datetime
import json
import logging
from pathlib import Path

# Add the parent directory to the path so we can import from the module
parent_dir = str(Path(__file__).parent.parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from evrmore_authentication import EvrmoreAuth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-auth-demo")

def run_demo():
    """Run the authentication demo."""
    logger.info("Initializing Evrmore Authentication demo...")
    
    # Initialize authentication
    try:
        auth = EvrmoreAuth(debug=True)
        logger.info("Successfully connected to Evrmore node and initialized authentication system")
    except Exception as e:
        logger.error(f"Failed to initialize authentication: {e}")
        sys.exit(1)

    # Generate a test address
    try:
        test_address, wif_key = auth.create_wallet_address()
        logger.info(f"Created new Evrmore address: {test_address}")
    except Exception as e:
        logger.error(f"Failed to generate test address: {e}")
        sys.exit(1)

    # Generate challenge
    try:
        challenge = auth.generate_challenge(test_address)
        logger.info(f"Generated authentication challenge: {challenge}")
    except Exception as e:
        logger.error(f"Failed to generate challenge: {e}")
        sys.exit(1)

    # Sign the challenge
    try:
        signature = auth.sign_message(wif_key, challenge)
        logger.info(f"Signed challenge with wallet: {signature}")
    except Exception as e:
        logger.error(f"Failed to sign challenge: {e}")
        sys.exit(1)

    # Authenticate
    try:
        session = auth.authenticate(test_address, challenge, signature)
        logger.info(f"Successfully authenticated with signature")
        logger.info(f"User ID: {session.user_id}")
        logger.info(f"JWT Token: {session.token[:20]}...")
        logger.info(f"Token expires: {session.expires_at}")
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        sys.exit(1)

    # Validate token
    try:
        token_data = auth.validate_token(session.token)
        logger.info(f"Token validated successfully")
        logger.info(f"Token payload: {json.dumps(token_data, indent=2)}")
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        sys.exit(1)

    # Get user by token
    try:
        user = auth.get_user_by_token(session.token)
        logger.info(f"Retrieved user by token: {user.evrmore_address}")
    except Exception as e:
        logger.error(f"Failed to get user by token: {e}")
        sys.exit(1)

    # Invalidate token
    try:
        result = auth.invalidate_token(session.token)
        logger.info(f"Token invalidated: {result}")
    except Exception as e:
        logger.error(f"Failed to invalidate token: {e}")
        sys.exit(1)

    logger.info("Demo completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(run_demo()) 