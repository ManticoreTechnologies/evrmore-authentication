#!/usr/bin/env python3
"""
OAuth 2.0 Example for Evrmore Authentication

This example demonstrates a complete OAuth 2.0 flow using the Evrmore Authentication library:
1. Register an OAuth client
2. Initiate the authorization flow
3. Simulate user sign-in with an Evrmore wallet
4. Exchange the authorization code for tokens
5. Use the access token to access protected resources
6. Refresh the access token
7. Revoke the tokens

Usage:
    python3 oauth_example.py
"""

import os
import sys
import time
import logging
import requests
from datetime import datetime, timedelta
import uuid
from urllib.parse import urlencode, parse_qs

# Add the parent directory to the path so we can import the library
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the Evrmore Authentication library
from evrmore_authentication import EvrmoreAuth
from evrmore_authentication.crypto import sign_message
from evrmore_authentication.models import User, OAuthClient, OAuthAuthorizationCode, OAuthToken

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('oauth-example')

# Evrmore Authentication instance
auth = EvrmoreAuth(debug=True)

def print_section(title):
    """Print a section title."""
    print('\n' + '=' * 80)
    print(f' {title} '.center(80, '='))
    print('=' * 80 + '\n')

def simulate_frontend_app():
    """Simulate a frontend application using OAuth 2.0 for authentication."""
    print_section("FRONTEND APP SIMULATION")
    
    # Step 1: Register an OAuth client (this would be done once by the app developer)
    print("1. Registering OAuth client...")
    client = auth.register_oauth_client(
        client_name="Example Frontend App",
        redirect_uris=["https://example.com/callback", "http://localhost:8000/callback"],
        client_uri="https://example.com",
        allowed_response_types=["code"],
        allowed_scopes=["profile", "email", "wallet"]
    )
    
    print(f"   Client registered successfully!")
    print(f"   Client ID: {client.client_id}")
    print(f"   Client Secret: {client.client_secret}")
    
    # Step 2: Initiate the authorization flow
    print("\n2. Initiating authorization flow...")
    
    # Normally this would be handled by redirecting the user to the authorization endpoint
    # Here we'll simulate it by creating the authorization URL
    auth_params = {
        "client_id": client.client_id,
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "profile email",
        "state": str(uuid.uuid4())  # Used to prevent CSRF attacks
    }
    
    auth_url = f"https://auth.example.com/oauth/authorize?{urlencode(auth_params)}"
    print(f"   Authorization URL: {auth_url}")
    print(f"   Redirecting user to authorization page...")
    
    # Step 3: User authenticates with their Evrmore wallet (simulation)
    print("\n3. Simulating user authentication with Evrmore wallet...")
    
    # Create a test wallet address and private key for demonstration
    # In a real app, the user would use their own wallet
    wallet_address, wif_key = auth.create_wallet_address()
    print(f"   Test wallet address: {wallet_address}")
    
    # Generate a challenge that would be shown to the user to sign
    auth_request_id = str(uuid.uuid4())
    challenge = auth._create_challenge_text(wallet_address)
    print(f"   Challenge: {challenge}")
    
    # User signs the challenge with their wallet
    signature = auth.sign_message(wif_key, challenge)
    print(f"   Signature: {signature[:20]}...")
    
    # In a real app, the frontend would send this to the backend
    login_data = {
        "evrmore_address": wallet_address,
        "challenge": challenge,
        "signature": signature,
        "auth_request_id": auth_request_id
    }
    print(f"   Sending login data to server...")
    
    # Step 4: Backend verifies signature and creates authorization code
    print("\n4. Backend verifies signature and creates authorization code...")
    
    # Verify the signature
    if not auth.verify_signature_only(wallet_address, challenge, signature):
        print("   ERROR: Signature verification failed!")
        return
    
    print("   Signature verified successfully!")
    
    # Get or create user
    user = User.get_by_address(wallet_address)
    if not user:
        user = User.create(wallet_address)
        print(f"   Created new user with ID: {user.id}")
    else:
        print(f"   Found existing user with ID: {user.id}")
    
    # Create authorization code
    redirect_uri = auth_params["redirect_uri"]
    scope = auth_params["scope"]
    auth_code = auth.create_authorization_code(
        client_id=client.client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=scope
    )
    
    print(f"   Created authorization code: {auth_code.code[:10]}...")
    
    # Construct redirect URL with code
    callback_url = f"{redirect_uri}?code={auth_code.code}&state={auth_params['state']}"
    print(f"   Redirecting to: {callback_url}")
    
    # Step 5: Exchange authorization code for tokens
    print("\n5. Frontend exchanges authorization code for tokens...")
    
    # Parse the code from the callback URL
    callback_params = parse_qs(callback_url.split('?')[1])
    code = callback_params['code'][0]
    state = callback_params['state'][0]
    
    # Verify state matches the original state (prevents CSRF)
    if state != auth_params['state']:
        print("   ERROR: State parameter mismatch!")
        return
    
    print("   State parameter verified!")
    
    # Exchange code for tokens
    token = auth.exchange_code_for_token(
        code=code,
        client_id=client.client_id,
        client_secret=client.client_secret,
        redirect_uri=redirect_uri
    )
    
    print(f"   Received access token: {token.access_token[:20]}...")
    print(f"   Received refresh token: {token.refresh_token[:20]}...")
    print(f"   Access token expires at: {token.access_token_expires_at}")
    
    # Step 6: Use the access token to access protected resources
    print("\n6. Using access token to access protected resources...")
    
    # Validate the token
    token_info = auth.validate_oauth_token(token.access_token)
    if token_info:
        user_id = token_info["user_id"]
        evrmore_address = token_info["evrmore_address"]
        scope = token_info["scope"]
        expires_at = token_info["expires_at"]
        
        print(f"   Token is valid for user: {user_id}")
        print(f"   Evrmore address: {evrmore_address}")
        print(f"   Scope: {scope}")
        print(f"   Expires at: {datetime.fromtimestamp(expires_at)}")
        
        # Get user profile
        user = User.get_by_id(user_id)
        if user:
            print(f"   User profile: {user.to_dict()}")
        else:
            print("   ERROR: User not found!")
    else:
        print("   ERROR: Token validation failed!")
        return
    
    # Step 7: Refresh the access token
    print("\n7. Refreshing the access token...")
    
    # Simulate token expiration
    print(f"   Waiting for token to expire...")
    time.sleep(1)  # In a real app, this would happen after the token expires
    
    # Refresh the token
    new_token = auth.refresh_token(
        refresh_token=token.refresh_token,
        client_id=client.client_id,
        client_secret=client.client_secret
    )
    
    print(f"   Received new access token: {new_token.access_token[:20]}...")
    print(f"   Received new refresh token: {new_token.refresh_token[:20]}...")
    print(f"   New access token expires at: {new_token.access_token_expires_at}")
    
    # Step 8: Revoke the tokens
    print("\n8. Revoking the tokens...")
    
    # Revoke the access token
    revoked = auth.revoke_oauth_token(
        token=new_token.access_token,
        client_id=client.client_id,
        client_secret=client.client_secret
    )
    
    if revoked:
        print("   Access token revoked successfully!")
    else:
        print("   ERROR: Failed to revoke access token!")
    
    print("\nOAuth 2.0 flow completed successfully!")

if __name__ == "__main__":
    # Ensure database exists with required tables
    from evrmore_authentication.database import SqliteManager
    db = SqliteManager()
    
    try:
        simulate_frontend_app()
    except Exception as e:
        logger.error(f"Error in OAuth example: {str(e)}", exc_info=True) 