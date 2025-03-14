# OAuth Client Example

This guide demonstrates how to implement an OAuth 2.0 client that authenticates with the Evrmore Authentication system. The example uses FastAPI to create a simple web application that leverages Evrmore Authentication's OAuth 2.0 server for authentication.

## Prerequisites

- Python 3.8+
- FastAPI and its dependencies (`pip3 install fastapi uvicorn`)
- `evrmore-authentication` package installed
- `requests` and `python-multipart` packages
- Running instance of Evrmore Authentication server with OAuth enabled

## Project Setup

Create a new directory for your OAuth client project:

```bash
mkdir evrmore-oauth-client
cd evrmore-oauth-client
```

Create a virtual environment and install the required packages:

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install fastapi uvicorn requests python-multipart
```

## OAuth 2.0 Client Implementation

### 1. Create the Client Configuration

Create a file named `config.py` with the following content:

```python
# OAuth client configuration
OAUTH_CLIENT_ID = "your-client-id"  # Replace with your registered client ID
OAUTH_CLIENT_SECRET = "your-client-secret"  # Replace with your client secret
OAUTH_REDIRECT_URI = "http://localhost:8001/callback"

# Evrmore Authentication server URLs
AUTH_SERVER_URL = "http://localhost:8000"  # Replace with your server URL
AUTHORIZATION_ENDPOINT = f"{AUTH_SERVER_URL}/oauth/auth"
TOKEN_ENDPOINT = f"{AUTH_SERVER_URL}/oauth/token"
USERINFO_ENDPOINT = f"{AUTH_SERVER_URL}/oauth/userinfo"
```

### 2. Implement the OAuth Client Application

Create a file named `oauth_client.py` with the following content:

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import requests
import urllib.parse
import os
import secrets
import json
from typing import Optional

from config import (
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_REDIRECT_URI,
    AUTHORIZATION_ENDPOINT,
    TOKEN_ENDPOINT,
    USERINFO_ENDPOINT
)

app = FastAPI(title="Evrmore OAuth Client")

# Create the templates and static directories if they don't exist
os.makedirs("templates", exist_ok=True)
os.makedirs("static", exist_ok=True)

# Create a simple index.html template
with open("templates/index.html", "w") as f:
    f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Evrmore OAuth Client</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .user-info { background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-top: 20px; }
        .btn { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; 
               text-decoration: none; border-radius: 5px; margin-top: 20px; }
        .logout-btn { background-color: #f44336; }
    </style>
</head>
<body>
    <h1>Evrmore OAuth Client Example</h1>
    {% if user %}
        <div class="user-info">
            <h2>Authenticated User</h2>
            <p><strong>User ID:</strong> {{ user.id }}</p>
            <p><strong>Evrmore Address:</strong> {{ user.evrmore_address }}</p>
            <p><strong>Scope:</strong> {{ user.scope }}</p>
            <pre>{{ user_json }}</pre>
            <a href="/logout" class="btn logout-btn">Logout</a>
        </div>
    {% else %}
        <p>You are not logged in.</p>
        <a href="/login" class="btn">Login with Evrmore</a>
    {% endif %}
</body>
</html>
    """)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory session storage (replace with a database in production)
sessions = {}

def get_current_user(request: Request) -> Optional[dict]:
    """Get the current user from the session cookie"""
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return None
    return sessions[session_id].get("user")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: Optional[dict] = Depends(get_current_user)):
    """Main page with login/logout functionality"""
    context = {
        "request": request,
        "user": user,
        "user_json": json.dumps(user, indent=2) if user else None
    }
    return templates.TemplateResponse("index.html", context)

@app.get("/login")
async def login(request: Request):
    """Redirect to the authorization server"""
    # Generate a random state parameter to prevent CSRF
    state = secrets.token_urlsafe(16)
    
    # Store the state in the session for verification later
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {"state": state}
    
    # Build the authorization URL
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "profile",
        "state": state
    }
    auth_url = f"{AUTHORIZATION_ENDPOINT}?{urllib.parse.urlencode(params)}"
    
    # Redirect to the authorization server
    response = RedirectResponse(url=auth_url)
    response.set_cookie(key="session_id", value=session_id, httponly=True)
    return response

@app.get("/callback")
async def callback(request: Request, code: str, state: str):
    """Handle the OAuth callback"""
    # Get the session
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(status_code=400, detail="Invalid session")
    
    # Verify the state parameter
    if state != sessions[session_id].get("state"):
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Exchange the authorization code for an access token
    token_data = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI
    }
    
    token_response = requests.post(TOKEN_ENDPOINT, json=token_data)
    
    if token_response.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to exchange code for token: {token_response.text}"
        )
    
    token_info = token_response.json()
    access_token = token_info.get("access_token")
    
    # Get user information with the access token
    user_response = requests.get(
        USERINFO_ENDPOINT,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    if user_response.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to get user info: {user_response.text}"
        )
    
    user_info = user_response.json()
    
    # Store the user information in the session
    sessions[session_id]["user"] = user_info
    sessions[session_id]["access_token"] = access_token
    
    # Redirect back to the home page
    return RedirectResponse(url="/")

@app.get("/logout")
async def logout(request: Request):
    """Log the user out by removing the session"""
    session_id = request.cookies.get("session_id")
    
    if session_id and session_id in sessions:
        # Clean up the session
        del sessions[session_id]
    
    # Redirect back to the home page
    response = RedirectResponse(url="/")
    response.delete_cookie(key="session_id")
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("oauth_client:app", host="0.0.0.0", port=8001, reload=True)
```

## Registering Your OAuth Client

Before running the client, you need to register it with the Evrmore Authentication server. You can use the provided script or API endpoints to register your client:

```bash
python3 -m scripts.register_oauth_client \
    --name "Example OAuth Client" \
    --redirect-uris "http://localhost:8001/callback" \
    --scopes "profile" \
    --client-type "confidential"
```

This will give you a client ID and client secret that you should update in your `config.py` file.

## Running the OAuth Client

Run the OAuth client application:

```bash
python3 oauth_client.py
```

The client will be available at `http://localhost:8001`.

## Testing the OAuth Flow

1. Visit `http://localhost:8001` in your browser
2. Click on the "Login with Evrmore" button
3. You will be redirected to the Evrmore Authentication server
4. If you're not already logged in, you'll need to authenticate with your Evrmore wallet
5. After authentication, you'll be asked to authorize the client to access your profile
6. Once authorized, you'll be redirected back to the client application with your user information displayed

## Understanding the OAuth 2.0 Flow

This example implements the Authorization Code Flow, which is the most secure OAuth 2.0 flow for web applications:

1. **Authorization Request**: The client redirects the user to the authorization server with client ID, redirect URI, and requested scope.
2. **User Authentication**: The user authenticates with the Evrmore Authentication server using their wallet.
3. **Authorization Grant**: After authentication, the server asks the user to authorize the client's access to their data.
4. **Authorization Code**: If authorized, the server redirects back to the client with an authorization code.
5. **Token Exchange**: The client exchanges the authorization code for an access token by making a server-to-server request that includes the client secret.
6. **Resource Access**: The client uses the access token to access protected resources (user information in this case).

## Security Considerations

For a production application, consider these security enhancements:

1. **Use HTTPS**: Always use HTTPS in production to protect tokens and sensitive information.
2. **Secure Storage**: Store tokens securely, preferably in an encrypted database rather than in memory.
3. **PKCE Extension**: Use PKCE (Proof Key for Code Exchange) for additional security, especially for public clients.
4. **Token Refresh**: Implement token refresh functionality to obtain new access tokens without requiring re-authentication.
5. **Validate JWTs**: Validate the JWT tokens cryptographically instead of just accepting them.

## Advanced Features

You can enhance this basic example with:

1. **Token Refresh**: Implement refresh token handling to maintain long-term sessions.
2. **Additional Scopes**: Request additional scopes based on your application's needs.
3. **Persistent Storage**: Use a database to store sessions and tokens.
4. **Single Sign-On**: Leverage the single sign-on capabilities of OAuth 2.0.
5. **Custom User Interface**: Improve the user interface for a better user experience.

## Example with Token Refresh

Here's an example of how to implement token refresh:

```python
@app.get("/refresh")
async def refresh_token(request: Request):
    """Refresh the access token"""
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return RedirectResponse(url="/login")
    
    refresh_token = sessions[session_id].get("refresh_token")
    if not refresh_token:
        return RedirectResponse(url="/login")
    
    # Exchange the refresh token for a new access token
    token_data = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    
    token_response = requests.post(TOKEN_ENDPOINT, json=token_data)
    
    if token_response.status_code != 200:
        # If refresh fails, redirect to login
        return RedirectResponse(url="/login")
    
    token_info = token_response.json()
    access_token = token_info.get("access_token")
    new_refresh_token = token_info.get("refresh_token")
    
    # Update the session with the new tokens
    sessions[session_id]["access_token"] = access_token
    if new_refresh_token:
        sessions[session_id]["refresh_token"] = new_refresh_token
    
    # Redirect back to the home page
    return RedirectResponse(url="/")
```

To handle a refresh token, you would need to store it when received during the initial token exchange and then use it when the access token expires.

## Troubleshooting

### Common Issues

1. **Invalid Client ID**: Make sure your client ID and secret are correctly registered with the Evrmore Authentication server.
2. **Redirect URI Mismatch**: The redirect URI in your client registration must exactly match the one in your application.
3. **Expired Tokens**: Access tokens expire after a set time. Use refresh tokens to get new ones.
4. **State Parameter Mismatch**: If the state parameter doesn't match, it could indicate a CSRF attack or a session problem.

### Debugging Tips

1. Check the server logs for detailed error messages.
2. Use browser developer tools to inspect the network requests.
3. Add more logging to your client application to track the flow.
4. Verify that your authorization and token endpoints are correct.

## Conclusion

This example demonstrates a basic OAuth 2.0 client implementation for Evrmore Authentication. You can use this as a starting point for integrating Evrmore wallet-based authentication into your web applications. 