# OAuth 2.0 Implementation

Evrmore Authentication includes a comprehensive OAuth 2.0 server implementation, allowing your application to function as an identity provider for third-party applications.

## Overview

The OAuth 2.0 implementation supports:

- Standard Authorization Code flow
- Access and refresh token management
- Scoped permissions
- User info endpoint
- Token revocation
- Client registration and management

## Setup and Configuration

### Database Configuration

The OAuth system requires a properly configured database. By default, it uses SQLite located at `./evrmore_authentication/data/evrmore_auth.db`.

1. **Set the database path in your `.env` file**:

```
SQLITE_DB_PATH=./evrmore_authentication/data/evrmore_auth.db
```

2. **Initialize the database**:

```bash
python3 -m scripts.db_manage init
```

This command creates the necessary tables for the OAuth system, including:
- `oauth_clients` - Stores registered OAuth client applications
- `oauth_authorization_codes` - Stores temporary authorization codes
- `oauth_tokens` - Stores access and refresh tokens

### Running the Authentication Server

Start the authentication server with:

```bash
python3 -m scripts.run_api_server --port 8001
```

The server provides all the OAuth endpoints needed for the authorization flow.

## Client Registration

Before using OAuth, you must register a client application. The system provides a dedicated script for this purpose.

### Using the Client Registration Script

The `scripts/register_oauth_client.py` script simplifies OAuth client registration:

```bash
python3 scripts/register_oauth_client.py register \
    --name "Your Application Name" \
    --redirects "http://your-app.com/callback" \
    --uri "http://your-app.com" \
    --scopes "profile,email" \
    --response-types "code"
```

Parameters:
- `--name`: Your application's name (displayed to users)
- `--redirects`: Comma-separated list of allowed redirect URIs
- `--uri`: Your application's main URI (optional)
- `--scopes`: Comma-separated list of scopes your app needs
- `--response-types`: Response types your app supports (usually "code")

### Managing Clients

You can list registered clients:

```bash
python3 scripts/register_oauth_client.py list
```

Or delete a client:

```bash
python3 scripts/register_oauth_client.py delete --client-id YOUR_CLIENT_ID
```

### Storing Client Credentials

The script will output client credentials that should be stored securely. For example:

```
Successfully registered new OAuth client:
  ID:             92fae2b2-f231-43a4-945c-8c9f1f737627
  Client ID:      d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0
  Client Secret:  XBBMQM9kppmbCyT5opG5FCZ0g89osYeKkrlNrmbIfKk
  Name:           FastAPI OAuth Example
  Redirect URIs:  http://localhost:8000/callback
  Scopes:         profile
  Response Types: code
```

We recommend creating a dedicated `.env.oauth` file to store these credentials:

```
# OAuth Client Credentials
OAUTH_CLIENT_ID=d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0
OAUTH_CLIENT_SECRET=XBBMQM9kppmbCyT5opG5FCZ0g89osYeKkrlNrmbIfKk
OAUTH_REDIRECT_URI=http://localhost:8000/callback

# Authorization Server Settings
AUTH_SERVER_URL=http://localhost:8001
```

## OAuth 2.0 Flow Implementation

The OAuth 2.0 implementation follows the standard Authorization Code flow:

### Step 1: Redirect to Authorization Endpoint

Redirect the user to the authorization endpoint:

```python
import uuid
from urllib.parse import urlencode

# Generate state parameter to prevent CSRF
state = str(uuid.uuid4())
session['oauth_state'] = state

# Build the authorization URL
params = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "response_type": "code",
    "scope": "profile email",
    "state": state
}

auth_url = f"{AUTH_SERVER}/oauth/authorize?{urlencode(params)}"
return redirect(auth_url)
```

### Step 2: User Authentication

The user will be presented with an authentication page where they:
1. Enter their Evrmore wallet address
2. Receive a challenge to sign
3. Sign the challenge with their wallet
4. Submit the signature for verification

### Step 3: Handle the Callback

When authentication succeeds, the user is redirected to your redirect URI with a code:

```python
def oauth_callback(code, state):
    # Verify state parameter
    if state != session.get('oauth_state'):
        return "Invalid state parameter", 400
    
    # Exchange code for tokens
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
    
    token_data = token_response.json()
    
    # Store tokens securely
    session['access_token'] = token_data["access_token"]
    session['refresh_token'] = token_data["refresh_token"]
    
    return redirect('/profile')
```

### Step 4: Access Protected Resources

Use the access token to fetch user info or access protected resources:

```python
def get_user_profile():
    access_token = session.get('access_token')
    
    response = requests.get(
        f"{AUTH_SERVER}/oauth/userinfo",
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    
    user_data = response.json()
    return render_template('profile.html', user=user_data)
```

### Step 5: Refresh Tokens

When the access token expires, use the refresh token to get a new one:

```python
def refresh_access_token():
    refresh_token = session.get('refresh_token')
    
    response = requests.post(
        f"{AUTH_SERVER}/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )
    
    token_data = response.json()
    
    # Update tokens
    session['access_token'] = token_data["access_token"]
    session['refresh_token'] = token_data["refresh_token"]
    
    return token_data
```

### Step 6: Logout (Token Revocation)

When the user logs out, revoke their tokens:

```python
def logout():
    access_token = session.get('access_token')
    
    requests.post(
        f"{AUTH_SERVER}/oauth/revoke",
        json={
            "token": access_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        }
    )
    
    # Clear session
    session.clear()
    return redirect('/')
```

## Security Best Practices

1. **Use HTTPS** in production environments
2. **Set secure cookie attributes**:
   - `httpOnly` - Prevents JavaScript access
   - `secure` - Ensures cookies are sent only over HTTPS
   - `sameSite=lax` - Protects against CSRF

3. **Validate state parameter** to prevent CSRF attacks
4. **Store client secrets securely** and never expose them client-side
5. **Implement proper error handling** for authentication failures
6. **Use refresh tokens** for longer sessions rather than extending access token lifetimes
7. **Revoke tokens** when users log out

For full example implementations, see the [FastAPI OAuth Example](../examples/oauth-client.md) in the Examples section. 