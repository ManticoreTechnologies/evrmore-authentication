# Examples

This section provides practical examples of using Evrmore Authentication in different scenarios.

## Basic Authentication Example

```python
from evrmore_authentication import EvrmoreAuth
from evrmore_rpc import EvrmoreClient

# Initialize the authentication system
client = EvrmoreClient()
auth = EvrmoreAuth(client)

# Generate a challenge for a user's Evrmore address
evrmore_address = "EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW"
challenge = auth.generate_challenge(evrmore_address)
print(f"Challenge: {challenge}")

# In a real application, the user would sign this challenge with their wallet
# For testing, we can use the Evrmore client to sign the message
signature = client.signmessage(evrmore_address, challenge)
print(f"Signature: {signature}")

# Authenticate the user with the signed challenge
session = auth.authenticate(evrmore_address, challenge, signature)
print(f"Token: {session.token}")
print(f"User ID: {session.user_id}")
print(f"Expires at: {session.expires_at}")

# Validate the token
payload = auth.validate_token(session.token)
print(f"Token payload: {payload}")

# Get the user by token
user = auth.get_user_by_token(session.token)
print(f"User: {user.evrmore_address}")

# Invalidate the token (logout)
auth.invalidate_token(session.token)
print("Token invalidated")
```

## FastAPI Integration Example

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from evrmore_authentication import EvrmoreAuth, get_current_user
from evrmore_authentication.exceptions import InvalidTokenError, UserNotFoundError

app = FastAPI(title="Evrmore Auth API")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
auth = EvrmoreAuth()

@app.post("/challenge")
async def generate_challenge(evrmore_address: str):
    """Generate a challenge for a user to sign with their Evrmore wallet."""
    challenge = auth.generate_challenge(evrmore_address)
    return {"challenge": challenge}

@app.post("/authenticate")
async def authenticate(evrmore_address: str, challenge: str, signature: str):
    """Authenticate a user with their signed challenge."""
    try:
        session = auth.authenticate(evrmore_address, challenge, signature)
        return {
            "token": session.token,
            "user_id": session.user_id,
            "evrmore_address": session.evrmore_address,
            "expires_at": session.expires_at
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/me")
async def get_current_user_info(current_user = Depends(get_current_user)):
    """Get information about the currently authenticated user."""
    return {
        "id": str(current_user.id),
        "evrmore_address": current_user.evrmore_address,
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at,
        "last_login": current_user.last_login
    }

@app.post("/logout")
async def logout(token: str):
    """Invalidate a JWT token (logout)."""
    try:
        auth.invalidate_token(token)
        return {"success": True}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

## Web Application Example

See the complete web application example in the [examples/web_auth_demo](https://github.com/manticoretechnologies/evrmore-authentication/tree/main/examples/web_auth_demo) directory. 