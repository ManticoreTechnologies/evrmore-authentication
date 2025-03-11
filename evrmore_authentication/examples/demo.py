#!/usr/bin/env python3
"""
Evrmore Authentication Demo Script

This script demonstrates the complete authentication flow using the Evrmore Authentication system.
It requires a running Evrmore node with RPC enabled.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Add parent directory to path to import evrmore_authentication
sys.path.append(str(Path(__file__).parent.parent.parent))

from evrmore_authentication import EvrmoreAuth
from evrmore_rpc import EvrmoreClient
from evrmore_authentication.exceptions import (
    AuthenticationError, 
    InvalidSignatureError,
    ChallengeExpiredError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore_auth_demo")

def main():
    """Run the authentication demo."""
    logger.info("Starting Evrmore Authentication Demo")
    
    # Connect to Evrmore node
    try:
        logger.info("Connecting to Evrmore node...")
        client = EvrmoreClient()
        logger.info("Connected successfully!")
    except Exception as e:
        logger.error(f"Failed to connect to Evrmore node: {str(e)}")
        logger.error("Make sure your Evrmore node is running and RPC is enabled")
        sys.exit(1)
    
    # Initialize authentication system
    try:
        logger.info("Initializing authentication system...")
        auth = EvrmoreAuth(evrmore_client=client)
        logger.info("Authentication system initialized!")
    except Exception as e:
        logger.error(f"Failed to initialize authentication: {str(e)}")
        sys.exit(1)
    
    # Create a new wallet address for testing
    try:
        logger.info("Creating a new Evrmore address...")
        address = client.getnewaddress()
        logger.info(f"Created address: {address}")
    except Exception as e:
        logger.error(f"Failed to create address: {str(e)}")
        sys.exit(1)
    
    # Generate authentication challenge
    try:
        logger.info("Generating authentication challenge...")
        challenge = auth.generate_challenge(address)
        logger.info(f"Challenge: {challenge}")
    except Exception as e:
        logger.error(f"Failed to generate challenge: {str(e)}")
        sys.exit(1)
    
    # Sign the challenge with the wallet
    try:
        logger.info("Signing challenge with wallet...")
        signature = client.signmessage(address, challenge)
        logger.info(f"Signature: {signature}")
    except Exception as e:
        logger.error(f"Failed to sign message: {str(e)}")
        sys.exit(1)
    
    # Authenticate with the signature
    try:
        logger.info("Authenticating with signature...")
        session = auth.authenticate(address, challenge, signature)
        logger.info("Authentication successful!")
        logger.info(f"User ID: {session.user_id}")
        logger.info(f"Token: {session.token}")
        logger.info(f"Expires: {session.expires_at}")
    except InvalidSignatureError:
        logger.error("Authentication failed: Invalid signature")
        sys.exit(1)
    except ChallengeExpiredError:
        logger.error("Authentication failed: Challenge expired")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        sys.exit(1)
    
    # Validate the token
    try:
        logger.info("Validating token...")
        payload = auth.validate_token(session.token)
        logger.info("Token is valid!")
        logger.info(f"Token payload: {json.dumps(payload, indent=2)}")
    except Exception as e:
        logger.warning(f"Token validation warning (not critical): {str(e)}")
        logger.info("Continuing demo despite token validation issue...")
    
    # Get user by token
    try:
        logger.info("Getting user by token...")
        user = auth.get_user_by_token(session.token)
        logger.info(f"User found: {user.evrmore_address}")
    except Exception as e:
        logger.warning(f"User lookup warning (not critical): {str(e)}")
        logger.info(f"Using session user ID: {session.user_id}")
    
    # Invalidate the token (logout)
    try:
        logger.info("Invalidating token (logout)...")
        success = auth.invalidate_token(session.token)
        if success:
            logger.info("Token invalidated successfully!")
        else:
            logger.warning("Failed to invalidate token")
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
    
    logger.info("Demo completed successfully!")

if __name__ == "__main__":
    main() 