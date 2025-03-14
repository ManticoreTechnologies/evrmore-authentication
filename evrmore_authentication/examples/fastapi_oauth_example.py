#!/usr/bin/env python3
"""
Evrmore Authentication OAuth 2.0 FastAPI Example
-----------------------------------------------
Manticore Technologies - https://manticore.technology

This example shows how to integrate Evrmore Authentication OAuth 2.0
with a FastAPI application.

To run this example:
    pip3 install fastapi uvicorn requests python-dotenv
    python3 fastapi_oauth_example.py

Then visit http://localhost:8000 in your browser.
"""

import os
import uuid
import json
import time
import requests
from urllib.parse import urlencode
from typing import Optional
from dotenv import load_dotenv
from pathlib import Path

from fastapi import FastAPI, Request, Response, Depends, Cookie, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Load environment from .env.oauth file if it exists, otherwise try .env
env_oauth_path = Path(__file__).resolve().parents[2] / '.env.oauth'
env_path = Path(__file__).resolve().parents[2] / '.env'

if env_oauth_path.exists():
    print(f"Loading OAuth environment from {env_oauth_path}")
    load_dotenv(env_oauth_path)
else:
    print(f"Loading default environment from {env_path}")
    load_dotenv(env_path)

# OAuth 2.0 configuration
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:8000/callback")
AUTH_SERVER = os.environ.get("AUTH_SERVER_URL", "http://localhost:8001")

print(f"Using OAuth Client ID: {CLIENT_ID}")
print(f"Redirect URI: {REDIRECT_URI}")
print(f"Auth Server: {AUTH_SERVER}")

# Verify required OAuth settings
if not CLIENT_ID or not CLIENT_SECRET:
    raise RuntimeError(
        "OAuth client credentials not found! Please run the following command and try again:\n"
        "python3 scripts/register_oauth_client.py register --name 'FastAPI OAuth Example' "
        "--redirects 'http://localhost:8000/callback' --uri 'http://localhost:8000'"
    )

# Create FastAPI app
app = FastAPI(title="Evrmore Authentication OAuth 2.0 Example")

# Create simple in-memory session store (use Redis or a database in production)
sessions = {}

# Configure OAuth2 password bearer for token validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with login button."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Evrmore Authentication Example</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }
            .login-button {
                display: inline-block;
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 4px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Evrmore Authentication OAuth 2.0 Example</h1>
        <p>This example demonstrates how to integrate Evrmore Authentication with a FastAPI application.</p>
        <a href="/login" class="login-button">Login with Evrmore</a>
    </body>
    </html>
    """

@app.get("/login")
async def login():
    """Redirect to the OAuth 2.0 authorization endpoint."""
    # Generate a random state parameter to prevent CSRF attacks
    state = str(uuid.uuid4())
    
    # Store the state in a session
    sessions[state] = {"created_at": time.time()}
    
    # Build the authorization URL
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "profile",
        "state": state
    }
    
    authorization_url = f"{AUTH_SERVER}/oauth/authorize?{urlencode(params)}"
    
    # Redirect to the authorization endpoint
    return RedirectResponse(authorization_url)

@app.post("/get-challenge")
async def get_challenge(request: Request):
    """Generate a challenge for the user to sign."""
    form_data = await request.form()
    evrmore_address = form_data.get("evrmore_address")
    state = form_data.get("state")
    client_id = form_data.get("client_id")
    redirect_uri = form_data.get("redirect_uri")
    
    if not evrmore_address:
        return RedirectResponse("/login")
    
    # Store the submission in session
    if state not in sessions:
        return RedirectResponse("/login")
    
    sessions[state].update({
        "evrmore_address": evrmore_address,
        "client_id": client_id,
        "redirect_uri": redirect_uri
    })
    
    # Get a challenge from the authentication server
    try:
        challenge_response = requests.post(
            f"{AUTH_SERVER}/challenge",
            json={
                "evrmore_address": evrmore_address,
                "expire_minutes": 10
            },
            headers={
                "Content-Type": "application/json"
            }
        )
        challenge_response.raise_for_status()
        
        try:
            challenge_data = challenge_response.json()
            print(f"Challenge response: {challenge_data}")
            
            if "challenge" not in challenge_data:
                return HTMLResponse(f"""
                <html>
                <body>
                    <h1>Error</h1>
                    <p>Invalid challenge response: {challenge_data}</p>
                    <a href="/login">Try Again</a>
                </body>
                </html>
                """)
                
            sessions[state]["challenge"] = challenge_data["challenge"]
            
            # Show the challenge to the user
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Sign Challenge</title>
                <style>
                    body {{{{
                        font-family: Arial, sans-serif;
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                        line-height: 1.6;
                    }}}}
                    .challenge-card {{{{
                        background-color: #f5f5f5;
                        border-radius: 8px;
                        padding: 20px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        margin-top: 20px;
                    }}}}
                    .form-group {{{{
                        margin-bottom: 15px;
                    }}}}
                    label {{{{
                        display: block;
                        margin-bottom: 5px;
                        font-weight: bold;
                    }}}}
                    input[type="text"] {{{{
                        width: 100%;
                        padding: 8px;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                    }}}}
                    .challenge-text {{{{
                        background: #e9e9e9;
                        padding: 10px;
                        border-radius: 4px;
                        font-family: monospace;
                        word-break: break-all;
                    }}}}
                    button {{{{
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        padding: 10px 15px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-weight: bold;
                    }}}}
                </style>
            </head>
            <body>
                <h1>Sign this challenge with your Evrmore wallet</h1>
                
                <div class="challenge-card">
                    <div class="form-group">
                        <label>Challenge to sign:</label>
                        <div class="challenge-text">{challenge_data["challenge"]}</div>
                        <p>Use your Evrmore wallet to sign this message, then paste the signature below.</p>
                    </div>
                    
                    <form action="/verify-signature" method="post">
                        <input type="hidden" name="state" value="{state}">
                        
                        <div class="form-group">
                            <label for="signature">Signature:</label>
                            <input type="text" id="signature" name="signature" 
                                   placeholder="Paste your signature here" required>
                        </div>
                        
                        <button type="submit">Verify Signature</button>
                    </form>
                </div>
            </body>
            </html>
            """)
        except ValueError as e:
            return HTMLResponse(f"""
            <html>
            <body>
                <h1>Error</h1>
                <p>Failed to parse challenge response: {challenge_response.text}</p>
                <a href="/login">Try Again</a>
            </body>
            </html>
            """)
    except requests.RequestException as e:
        return HTMLResponse(f"""
        <html>
        <body>
            <h1>Error</h1>
            <p>Failed to generate challenge: {str(e)}</p>
            <a href="/login">Try Again</a>
        </body>
        </html>
        """)

@app.post("/verify-signature")
async def verify_signature(request: Request):
    """Verify the signature and complete the authentication."""
    form_data = await request.form()
    signature = form_data.get("signature")
    state = form_data.get("state")
    
    if not signature or state not in sessions:
        return RedirectResponse("/login")
    
    session_data = sessions[state]
    evrmore_address = session_data.get("evrmore_address")
    challenge = session_data.get("challenge")
    client_id = session_data.get("client_id")
    redirect_uri = session_data.get("redirect_uri")
    
    if not evrmore_address or not challenge or not client_id or not redirect_uri:
        return RedirectResponse("/login")
    
    # Authenticate with the server
    try:
        auth_response = requests.post(
            f"{AUTH_SERVER}/authenticate",
            json={
                "evrmore_address": evrmore_address,
                "challenge": challenge,
                "signature": signature
            },
            headers={
                "Content-Type": "application/json"
            }
        )
        auth_response.raise_for_status()
        auth_data = auth_response.json()
        
        if "token" not in auth_data:
            return HTMLResponse("<html><body><h1>Authentication Failed</h1><p>Invalid signature or server error.</p><a href='/login'>Try Again</a></body></html>")
        
        # Get authorization code
        code_response = requests.post(
            f"{AUTH_SERVER}/oauth/authorize",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth_data['token']}"
            },
            json={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "profile email",
                "state": state
            }
        )
        code_response.raise_for_status()
        code_data = code_response.json()
        
        if "code" not in code_data:
            return HTMLResponse("<html><body><h1>Error</h1><p>Failed to get authorization code.</p><a href='/login'>Try Again</a></body></html>")
            
        # Redirect to callback
        return RedirectResponse(f"{redirect_uri}?code={code_data['code']}&state={state}")
    except requests.RequestException as e:
        return HTMLResponse(f"""
        <html>
        <body>
            <h1>Error</h1>
            <p>Authentication failed: {str(e)}</p>
            <a href="/login">Try Again</a>
        </body>
        </html>
        """)

@app.get("/callback")
async def callback(code: str, state: str, response: Response):
    """Handle the OAuth callback from Evrmore Authentication."""
    # Verify the state parameter to prevent CSRF attacks
    if state not in sessions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter"
        )
    
    print(f"Received callback with code: {code} and state: {state}")
    print(f"Session data: {sessions[state]}")
    
    # Exchange the authorization code for tokens
    try:
        print(f"Exchanging code for token with AUTH_SERVER: {AUTH_SERVER}")
        print(f"Using client ID: {CLIENT_ID}")
        print(f"Using redirect URI: {REDIRECT_URI}")
        
        token_response = requests.post(
            f"{AUTH_SERVER}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        
        print(f"Token response status: {token_response.status_code}")
        print(f"Token response headers: {dict(token_response.headers)}")
        
        try:
            print(f"Token response content: {token_response.text}")
            token_data = token_response.json()
            print(f"Token data: {token_data}")
        except Exception as e:
            print(f"Error parsing token response JSON: {str(e)}")
            
        token_response.raise_for_status()
        
        # Store the tokens in the session
        sessions[state].update({
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "expires_in": token_data["expires_in"],
            "scope": token_data["scope"]
        })
        
        # Set a secure cookie with the session ID
        response = RedirectResponse("/profile")
        response.set_cookie(
            key="session_id",
            value=state,
            httponly=True,
            max_age=3600,
            secure=True,
            samesite="lax"
        )
        
        return response
        
    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error exchanging code for token: {str(e)}"
        )

@app.get("/profile", response_class=HTMLResponse)
async def profile(session_id: Optional[str] = Cookie(None)):
    """Show the user's profile information."""
    # Verify session
    if not session_id or session_id not in sessions:
        return RedirectResponse("/login")
    
    session = sessions[session_id]
    if "access_token" not in session:
        return RedirectResponse("/login")
    
    # Get user profile using access token
    try:
        profile_response = requests.get(
            f"{AUTH_SERVER}/oauth/userinfo",
            headers={
                "Authorization": f"Bearer {session['access_token']}"
            }
        )
        profile_response.raise_for_status()
        
        user_data = profile_response.json()
        
        # Display profile
        address = user_data.get("address", "")
        username = user_data.get("preferred_username", address)
        user_id = user_data.get("sub", "")
        email = user_data.get("email", "")
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Your Profile</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .profile {{
                    background-color: #f5f5f5;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .button {{
                    display: inline-block;
                    background-color: #4CAF50;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 4px;
                    font-weight: bold;
                    margin-right: 10px;
                }}
                .logout {{
                    background-color: #f44336;
                }}
                .token-info {{
                    background-color: #efefef;
                    padding: 10px;
                    border-radius: 4px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <h1>Your Profile</h1>
            
            <div class="profile">
                <h2>{username}</h2>
                <p><strong>Evrmore Address:</strong> {address}</p>
                <p><strong>User ID:</strong> {user_id}</p>
                <p><strong>Email:</strong> {email}</p>
            </div>
            
            <a href="/refresh" class="button">Refresh Token</a>
            <a href="/logout" class="button logout">Logout</a>
            
            <div class="token-info">
                <h3>Access Token (first 50 chars):</h3>
                {session['access_token'][:50]}...
                
                <h3>Token Details:</h3>
                <pre>{json.dumps(session, indent=2)}</pre>
            </div>
        </body>
        </html>
        """
    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching profile: {str(e)}"
        )

@app.get("/refresh")
async def refresh_token(session_id: Optional[str] = Cookie(None)):
    """Refresh the access token."""
    # Verify session
    if not session_id or session_id not in sessions:
        return RedirectResponse("/login")
    
    session = sessions[session_id]
    if "refresh_token" not in session:
        return RedirectResponse("/login")
    
    # Refresh the token
    try:
        refresh_response = requests.post(
            f"{AUTH_SERVER}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": session["refresh_token"],
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            }
        )
        refresh_response.raise_for_status()
        
        token_data = refresh_response.json()
        
        # Update session with new tokens
        session.update({
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "expires_in": token_data["expires_in"],
            "refreshed_at": time.time()
        })
        
        return RedirectResponse("/profile")
        
    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error refreshing token: {str(e)}"
        )

@app.get("/logout")
async def logout(response: Response, session_id: Optional[str] = Cookie(None)):
    """Logout and revoke tokens."""
    # Verify session
    if not session_id or session_id not in sessions:
        return RedirectResponse("/")
    
    session = sessions[session_id]
    
    # Revoke the access token if it exists
    if "access_token" in session:
        try:
            revoke_response = requests.post(
                f"{AUTH_SERVER}/oauth/revoke",
                json={
                    "token": session["access_token"],
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET
                }
            )
            revoke_response.raise_for_status()
        except requests.RequestException:
            # Continue with logout even if token revocation fails
            pass
    
    # Clear the session
    if session_id in sessions:
        del sessions[session_id]
    
    # Clear the session cookie
    response = RedirectResponse("/")
    response.delete_cookie("session_id")
    
    return response

# API endpoints protected with OAuth
class UserProfile(BaseModel):
    """User profile response model."""
    user_id: str
    address: str
    username: Optional[str] = None
    email: Optional[str] = None

# Helper to get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get the current user from an OAuth token."""
    try:
        # Verify token with Evrmore Authentication
        profile_response = requests.get(
            f"{AUTH_SERVER}/oauth/userinfo",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
        profile_response.raise_for_status()
        
        user_data = profile_response.json()
        return user_data
        
    except requests.RequestException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/me", response_model=UserProfile)
async def api_me(user_data: dict = Depends(get_current_user)):
    """Get the current user's profile (protected API endpoint)."""
    return {
        "user_id": user_data.get("sub", ""),
        "address": user_data.get("address", ""),
        "username": user_data.get("preferred_username", ""),
        "email": user_data.get("email", "")
    }

if __name__ == "__main__":
    import uvicorn
    import time
    
    print(f"=== Evrmore Authentication OAuth 2.0 FastAPI Example ===")
    print(f"CLIENT_ID: {CLIENT_ID}")
    print(f"REDIRECT_URI: {REDIRECT_URI}")
    print(f"AUTH_SERVER: {AUTH_SERVER}")
    print(f"Starting server on http://localhost:8000")
    
    uvicorn.run(app, host="0.0.0.0", port=8000) 