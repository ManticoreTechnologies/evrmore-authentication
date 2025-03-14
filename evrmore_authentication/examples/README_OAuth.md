# Evrmore Authentication OAuth 2.0

This guide explains how to integrate Evrmore Authentication's OAuth 2.0 functionality into your application.

## Overview

Evrmore Authentication OAuth 2.0 allows users to authenticate using their Evrmore wallet and authorize applications to access their data securely. The implementation follows the OAuth 2.0 Authorization Code Flow, which is the most secure and recommended flow for web applications.

## Features

- **OAuth 2.0 Authorization Code Flow** - Complete implementation of the standard flow
- **JWT-Based Authentication** - Secure tokens with configurable signing algorithms (HS256/RS256)
- **Token Refresh** - Support for refresh tokens to maintain authentication state
- **Token Revocation** - Ability to revoke tokens (logout)
- **Scope-Based Access Control** - Control what resources applications can access
- **User Profile Endpoint** - Standard OpenID Connect userinfo endpoint

## Getting Started

### 1. Register an OAuth Client

Before using OAuth, you need to register your application as an OAuth client. This can be done through the API or web interface.

```python
import requests

# Register a new client
response = requests.post(
    "https://auth.manticore.technology/oauth/clients",
    json={
        "client_name": "My Application",
        "redirect_uris": "https://myapp.com/callback",
        "scope": "profile email",
        "grant_types": "authorization_code,refresh_token",
        "response_types": "code"
    },
    headers={
        "Authorization": f"Bearer {admin_token}"  # Admin token required
    }
)

client_data = response.json()
client_id = client_data["client_id"]
client_secret = client_data["client_secret"]
```

### 2. Implement the Authorization Flow

#### Step 1: Redirect the User to the Authorization Endpoint

```python
import uuid
from urllib.parse import urlencode

# Generate a random state parameter to prevent CSRF attacks
state = str(uuid.uuid4())

# Store the state in your session management system
session['oauth_state'] = state

# Build the authorization URL
params = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "response_type": "code",
    "scope": "profile email",
    "state": state
}

auth_url = f"https://auth.manticore.technology/oauth/authorize?{urlencode(params)}"

# Redirect the user to this URL
return redirect(auth_url)
```

#### Step 2: Handle the Callback

```python
def oauth_callback(request):
    # Get the code and state from the request
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    # Verify the state parameter to prevent CSRF attacks
    if state != session.get('oauth_state'):
        return HttpResponse("Invalid state parameter", status=400)
    
    # Exchange the authorization code for tokens
    response = requests.post(
        "https://auth.manticore.technology/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        }
    )
    
    token_data = response.json()
    
    # Store the tokens securely
    session['access_token'] = token_data["access_token"]
    session['refresh_token'] = token_data["refresh_token"]
    session['expires_in'] = token_data["expires_in"]
    
    # Redirect to protected area
    return redirect('/profile')
```

#### Step 3: Access Protected Resources

```python
def get_user_profile(request):
    access_token = session.get('access_token')
    
    if not access_token:
        return redirect('/login')
    
    # Get user profile using access token
    response = requests.get(
        "https://auth.manticore.technology/oauth/userinfo",
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    
    if response.status_code == 401:
        # Token has expired, try to refresh
        refresh_token = session.get('refresh_token')
        if refresh_token:
            new_tokens = refresh_access_token(refresh_token)
            if new_tokens:
                access_token = new_tokens["access_token"]
                # Update the session with new tokens
                session['access_token'] = access_token
                session['refresh_token'] = new_tokens["refresh_token"]
                
                # Retry the request
                response = requests.get(
                    "https://auth.manticore.technology/oauth/userinfo",
                    headers={
                        "Authorization": f"Bearer {access_token}"
                    }
                )
    
    if response.status_code != 200:
        # Something went wrong, redirect to login
        return redirect('/login')
    
    user_data = response.json()
    return render_template('profile.html', user=user_data)
```

#### Step 4: Refresh Tokens

```python
def refresh_access_token(refresh_token):
    response = requests.post(
        "https://auth.manticore.technology/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        }
    )
    
    if response.status_code != 200:
        return None
    
    return response.json()
```

#### Step 5: Logout (Revoke Tokens)

```python
def logout(request):
    access_token = session.get('access_token')
    
    if access_token:
        # Revoke the token
        requests.post(
            "https://auth.manticore.technology/oauth/revoke",
            json={
                "token": access_token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            }
        )
    
    # Clear the session
    session.clear()
    
    return redirect('/')
```

## Example Applications

This repository includes example applications to demonstrate the OAuth 2.0 flow:

1. **test_oauth.py** - A command-line application that walks through the OAuth flow
2. **fastapi_oauth_example.py** - A FastAPI web application that demonstrates the full OAuth flow

To run the FastAPI example:

```bash
pip3 install fastapi uvicorn requests
python3 fastapi_oauth_example.py
```

Then visit http://localhost:8000 in your browser.

## Security Considerations

1. **Always use HTTPS** in production environments
2. **Store client secrets securely** and never expose them in client-side code
3. **Validate the state parameter** to prevent CSRF attacks
4. **Use secure cookies** for session management (httpOnly, secure, sameSite)
5. **Validate tokens** on every request
6. **Implement proper error handling** for authentication failures
7. **Use refresh tokens** to maintain long-lived sessions securely
8. **Revoke tokens** when users log out

## REST API Endpoints

Evrmore Authentication provides the following OAuth 2.0 endpoints:

- **POST /oauth/clients** - Register a new OAuth client
- **GET/POST /oauth/authorize** - Start the authorization process
- **POST /oauth/token** - Exchange authorization codes or refresh tokens
- **GET /oauth/userinfo** - Get the authenticated user's profile
- **POST /oauth/revoke** - Revoke tokens

For detailed API documentation, refer to the Evrmore Authentication API documentation.

## Questions and Support

If you have any questions or need assistance, please contact:
- Email: dev@manticore.technology
- GitHub: https://github.com/manticoretechnologies 