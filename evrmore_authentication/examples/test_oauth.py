#!/usr/bin/env python3
"""
Evrmore Authentication OAuth 2.0 Test Script
-------------------------------------------
Manticore Technologies - https://manticore.technology

This script demonstrates how to use the Evrmore Authentication OAuth 2.0 API
from a Python backend application.
"""

import os
import sys
import requests
import json
import uuid
import time
from urllib.parse import urlencode, parse_qs

# Configure your application
CLIENT_ID = "your-client-id"  # Get this from registering your app
CLIENT_SECRET = "your-client-secret"  # Get this from registering your app
REDIRECT_URI = "http://localhost:8000/callback"
AUTH_SERVER = "https://auth.manticore.technology"  # Or your custom auth server URL

def register_client():
    """Register a new OAuth 2.0 client with the Evrmore Authentication server."""
    print("Registering a new OAuth client...")
    
    # First, you need to authenticate with your admin user
    # This would typically be done through the web interface
    # For this example, we'll use a direct API call
    
    # Get an auth token for the admin
    # In practice, this would be done through the regular Evrmore wallet authentication
    # For this example, we assume you already have a token
    admin_token = input("Enter your admin JWT token: ")
    
    # Register a new client
    response = requests.post(
        f"{AUTH_SERVER}/oauth/clients",
        json={
            "client_name": "Example Application",
            "redirect_uris": f"{REDIRECT_URI}",
            "scope": "profile email",
            "grant_types": "authorization_code,refresh_token",
            "response_types": "code"
        },
        headers={
            "Authorization": f"Bearer {admin_token}"
        }
    )
    
    if response.status_code != 200:
        print(f"Error registering client: {response.text}")
        return None
    
    client_data = response.json()
    print(f"Client registered successfully!")
    print(f"Client ID: {client_data['client_id']}")
    print(f"Client Secret: {client_data['client_secret']}")
    
    # Save these values to your environment or configuration
    return client_data

def get_authorization_url(client_id, redirect_uri, scope="profile", state=None):
    """Generate the authorization URL for the user to visit."""
    if state is None:
        state = str(uuid.uuid4())
        
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state
    }
    
    auth_url = f"{AUTH_SERVER}/oauth/authorize?{urlencode(params)}"
    return auth_url, state

def exchange_code_for_token(code, client_id, client_secret, redirect_uri):
    """Exchange an authorization code for access and refresh tokens."""
    response = requests.post(
        f"{AUTH_SERVER}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret
        }
    )
    
    if response.status_code != 200:
        print(f"Error exchanging code for token: {response.text}")
        return None
    
    return response.json()

def refresh_access_token(refresh_token, client_id, client_secret):
    """Refresh an access token using a refresh token."""
    response = requests.post(
        f"{AUTH_SERVER}/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret
        }
    )
    
    if response.status_code != 200:
        print(f"Error refreshing token: {response.text}")
        return None
    
    return response.json()

def get_user_profile(access_token):
    """Get the user's profile using an access token."""
    response = requests.get(
        f"{AUTH_SERVER}/oauth/userinfo",
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    
    if response.status_code != 200:
        print(f"Error getting user profile: {response.text}")
        return None
    
    return response.json()

def revoke_token(token, client_id, client_secret):
    """Revoke an access or refresh token."""
    response = requests.post(
        f"{AUTH_SERVER}/oauth/revoke",
        json={
            "token": token,
            "client_id": client_id,
            "client_secret": client_secret
        }
    )
    
    if response.status_code != 200:
        print(f"Error revoking token: {response.text}")
        return False
    
    return response.json().get("success", False)

def simulate_web_server():
    """Simulate a web server that handles the OAuth 2.0 flow."""
    print("\n=== Evrmore Authentication OAuth 2.0 Test ===\n")
    
    # Use provided client ID/secret or register a new client
    client_id = os.environ.get("OAUTH_CLIENT_ID") or CLIENT_ID
    client_secret = os.environ.get("OAUTH_CLIENT_SECRET") or CLIENT_SECRET
    
    if client_id == "your-client-id" or client_secret == "your-client-secret":
        print("No client credentials found. You can register a new client or enter existing credentials.")
        register_new = input("Register a new client? (y/n): ").lower() == 'y'
        
        if register_new:
            client_data = register_client()
            if client_data:
                client_id = client_data["client_id"]
                client_secret = client_data["client_secret"]
        else:
            client_id = input("Enter your client ID: ")
            client_secret = input("Enter your client secret: ")
    
    # Step 1: Generate an authorization URL
    auth_url, state = get_authorization_url(client_id, REDIRECT_URI, "profile email")
    print(f"\n1. Direct the user to this URL to authenticate:")
    print(f"\n{auth_url}\n")
    
    # Step 2: User visits the URL, authenticates with their Evrmore wallet, and is redirected back
    print("\n2. After the user authenticates, they will be redirected to your redirect_uri")
    print("   For example: http://localhost:8000/callback?code=abc123&state=xyz789")
    
    callback_url = input("\nEnter the full callback URL after authentication: ")
    
    # Extract the code and state from the callback URL
    query_params = parse_qs(callback_url.split('?', 1)[1] if '?' in callback_url else '')
    code = query_params.get('code', [''])[0]
    returned_state = query_params.get('state', [''])[0]
    
    # Verify state to prevent CSRF attacks
    if returned_state != state:
        print("Error: State parameter mismatch. Possible CSRF attack.")
        return
    
    print(f"\nCode: {code}")
    print(f"State validated: {returned_state == state}")
    
    # Step 3: Exchange the code for tokens
    print("\n3. Exchanging authorization code for tokens...")
    token_data = exchange_code_for_token(code, client_id, client_secret, REDIRECT_URI)
    
    if not token_data:
        print("Failed to exchange code for tokens.")
        return
    
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]
    expires_in = token_data["expires_in"]
    
    print(f"Access token: {access_token[:20]}...")
    print(f"Refresh token: {refresh_token[:20]}...")
    print(f"Expires in: {expires_in} seconds")
    
    # Step 4: Use the access token to get user information
    print("\n4. Getting user profile with access token...")
    user_profile = get_user_profile(access_token)
    
    if user_profile:
        print(f"User ID: {user_profile.get('sub')}")
        print(f"Evrmore Address: {user_profile.get('address')}")
        print(f"Username: {user_profile.get('preferred_username')}")
        print(f"Email: {user_profile.get('email')}")
    
    # Step 5: Simulate token expiration and refresh
    print("\n5. Simulating token refresh (in a real app, this would happen when the token expires)...")
    input("Press Enter to simulate refreshing the token...")
    
    refreshed_token_data = refresh_access_token(refresh_token, client_id, client_secret)
    
    if refreshed_token_data:
        new_access_token = refreshed_token_data["access_token"]
        new_refresh_token = refreshed_token_data["refresh_token"]
        
        print(f"New access token: {new_access_token[:20]}...")
        print(f"New refresh token: {new_refresh_token[:20]}...")
    
    # Step 6: Revoke the token (logout)
    print("\n6. Revoking token (logout)...")
    input("Press Enter to revoke the token (logout)...")
    
    success = revoke_token(
        refreshed_token_data["access_token"] if refreshed_token_data else access_token,
        client_id,
        client_secret
    )
    
    if success:
        print("Token revoked successfully!")
    else:
        print("Failed to revoke token.")
    
    print("\nOAuth 2.0 test completed!")

if __name__ == "__main__":
    simulate_web_server() 