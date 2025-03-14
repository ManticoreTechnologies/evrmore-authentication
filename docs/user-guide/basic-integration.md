# Basic Integration

This guide demonstrates how to integrate Evrmore Authentication into your application using various methods, from direct API calls to framework integrations.

## Installation

Install the package using pip:

```bash
pip3 install evrmore-authentication
```

## Configuration

Create a `.env` file in your project root:

```ini
# SQLite configuration
SQLITE_DB_PATH=./data/evrmore_auth.db

# JWT configuration
JWT_SECRET=your-secure-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Challenge configuration
CHALLENGE_EXPIRE_MINUTES=10

# Debug mode
EVRMORE_AUTH_DEBUG=false

# Logging
LOG_LEVEL=INFO
```

## Direct Integration

You can use the `EvrmoreAuth` class directly in your Python application:

```python
from evrmore_authentication import EvrmoreAuth

# Initialize the authentication system
auth = EvrmoreAuth()

# Generate a challenge for a user's Evrmore address
challenge = auth.generate_challenge("EXaMPLeEvRMoReAddResS")

# Verify the signature provided by the user
session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature="signed_challenge_from_wallet"
)

# Use the token for authentication
token = session.token

# Validate a token
token_data = auth.validate_token(token)

# Get user from token
user = auth.get_user_by_token(token)

# Invalidate a token (logout)
auth.invalidate_token(token)
```

## API Server Integration

The package includes a ready-to-use FastAPI server with the following endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenge` | POST | Generate a challenge for a user |
| `/authenticate` | POST | Authenticate with a signed challenge |
| `/validate` | GET | Validate a JWT token |
| `/me` | GET | Get authenticated user information |
| `/logout` | POST | Invalidate a JWT token (logout) |

### Running the API Server

```bash
python3 -m scripts.run_api_server --host 0.0.0.0 --port 8000
```

### API Client Example

```python
import requests

# Generate a challenge
response = requests.post(
    "http://localhost:8000/challenge",
    json={"evrmore_address": "EXaMPLeEvRMoReAddResS"}
)
challenge_data = response.json()
challenge = challenge_data["challenge"]

# User signs the challenge with their wallet...
signature = "signature_from_wallet"

# Authenticate with the signed challenge
response = requests.post(
    "http://localhost:8000/authenticate",
    json={
        "evrmore_address": "EXaMPLeEvRMoReAddResS",
        "challenge": challenge,
        "signature": signature
    }
)
auth_data = response.json()
token = auth_data["token"]

# Use the token for authenticated requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://localhost:8000/me", headers=headers)
user_data = response.json()

# Logout
response = requests.post(
    "http://localhost:8000/logout", 
    headers=headers
)
```

## FastAPI Integration

To integrate with your own FastAPI application:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from evrmore_authentication import EvrmoreAuth, AuthException

app = FastAPI(title="My API with Evrmore Authentication")
auth = EvrmoreAuth()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Helper to get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        user = auth.get_user_by_token(token)
        return user
    except AuthException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

# Challenge generation endpoint
@app.post("/challenge")
async def generate_challenge(data: dict):
    evrmore_address = data.get("evrmore_address")
    if not evrmore_address:
        raise HTTPException(status_code=400, detail="Evrmore address is required")
    
    try:
        challenge = auth.generate_challenge(evrmore_address)
        return {"challenge": challenge}
    except AuthException as e:
        raise HTTPException(status_code=400, detail=str(e))

# Authentication endpoint
@app.post("/authenticate")
async def authenticate(data: dict):
    evrmore_address = data.get("evrmore_address")
    challenge = data.get("challenge")
    signature = data.get("signature")
    
    if not all([evrmore_address, challenge, signature]):
        raise HTTPException(status_code=400, detail="Missing required parameters")
    
    try:
        session = auth.authenticate(
            evrmore_address=evrmore_address,
            challenge=challenge,
            signature=signature
        )
        return {
            "token": session.token,
            "expires_at": session.expires_at.isoformat()
        }
    except AuthException as e:
        raise HTTPException(status_code=401, detail=str(e))

# Protected endpoint
@app.get("/me")
async def get_me(user = Depends(get_current_user)):
    return {
        "id": user.id,
        "evrmore_address": user.evrmore_address,
        "username": user.username
    }

# Logout endpoint
@app.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    try:
        auth.invalidate_token(token)
        return {"success": True}
    except AuthException as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## Flask Integration

To integrate with Flask:

```python
from flask import Flask, request, jsonify
from evrmore_authentication import EvrmoreAuth, AuthException
import functools

app = Flask(__name__)
auth = EvrmoreAuth()

# Decorator for protected routes
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Validate token and get user
            user = auth.get_user_by_token(token)
            return f(user, *args, **kwargs)
        except AuthException as e:
            return jsonify({'error': str(e)}), 401
        
    return decorated

@app.route('/challenge', methods=['POST'])
def generate_challenge():
    data = request.get_json()
    evrmore_address = data.get('evrmore_address')
    
    if not evrmore_address:
        return jsonify({'error': 'Evrmore address is required'}), 400
    
    try:
        challenge = auth.generate_challenge(evrmore_address)
        return jsonify({'challenge': challenge})
    except AuthException as e:
        return jsonify({'error': str(e)}), 400

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    evrmore_address = data.get('evrmore_address')
    challenge = data.get('challenge')
    signature = data.get('signature')
    
    if not all([evrmore_address, challenge, signature]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    try:
        session = auth.authenticate(
            evrmore_address=evrmore_address,
            challenge=challenge,
            signature=signature
        )
        return jsonify({
            'token': session.token,
            'expires_at': session.expires_at.isoformat()
        })
    except AuthException as e:
        return jsonify({'error': str(e)}), 401

@app.route('/me', methods=['GET'])
@token_required
def get_me(user):
    return jsonify({
        'id': user.id,
        'evrmore_address': user.evrmore_address,
        'username': user.username
    })

@app.route('/logout', methods=['POST'])
@token_required
def logout(user):
    token = request.headers.get('Authorization').split(' ')[1]
    try:
        auth.invalidate_token(token)
        return jsonify({'success': True})
    except AuthException as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
```

## Django Integration

Create a Django authentication backend:

```python
# myapp/auth_backend.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from evrmore_authentication import EvrmoreAuth

class EvrmoreAuthBackend(BaseBackend):
    def authenticate(self, request, token=None):
        if not token:
            return None
        
        auth = EvrmoreAuth()
        try:
            evrmore_user = auth.get_user_by_token(token)
            # Get or create Django user
            user, created = User.objects.get_or_create(
                username=evrmore_user.evrmore_address,
                defaults={
                    'email': evrmore_user.email or '',
                    'first_name': evrmore_user.username or ''
                }
            )
            return user
        except Exception:
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
```

Add API views:

```python
# myapp/views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from evrmore_authentication import EvrmoreAuth
from django.contrib.auth import authenticate, login, logout

auth = EvrmoreAuth()

@csrf_exempt
@require_http_methods(["POST"])
def challenge(request):
    try:
        data = json.loads(request.body)
        evrmore_address = data.get('evrmore_address')
        
        if not evrmore_address:
            return JsonResponse({'error': 'Evrmore address is required'}, status=400)
        
        challenge = auth.generate_challenge(evrmore_address)
        return JsonResponse({'challenge': challenge})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
@require_http_methods(["POST"])
def authenticate_user(request):
    try:
        data = json.loads(request.body)
        evrmore_address = data.get('evrmore_address')
        challenge = data.get('challenge')
        signature = data.get('signature')
        
        if not all([evrmore_address, challenge, signature]):
            return JsonResponse({'error': 'Missing required parameters'}, status=400)
        
        session = auth.authenticate(
            evrmore_address=evrmore_address,
            challenge=challenge,
            signature=signature
        )
        
        # Authenticate with Django
        user = authenticate(request, token=session.token)
        if user:
            login(request, user)
        
        return JsonResponse({
            'token': session.token,
            'expires_at': session.expires_at.isoformat()
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=401)

def user_info(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'id': request.user.id,
        'username': request.user.username,
        'email': request.user.email
    })

@csrf_exempt
@require_http_methods(["POST"])
def logout_user(request):
    # Get token from header
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            auth.invalidate_token(token)
            logout(request)
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid Authorization header'}, status=400)
```

Configure Django settings:

```python
# settings.py
AUTHENTICATION_BACKENDS = [
    'myapp.auth_backend.EvrmoreAuthBackend',
    'django.contrib.auth.backends.ModelBackend',  # Default backend
]
```

## Next Steps

Once you've integrated basic authentication, consider:

1. Implementing the [OAuth 2.0 flow](oauth-implementation.md) for third-party integrations
2. Adding [event hooks](../api-reference/event-hooks.md) for custom behavior
3. Implementing custom [user management](../api-reference/core-api.md#user-management)
4. Exploring [advanced features](debugging.md) for enhanced security 