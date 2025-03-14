# FastAPI Integration Guide

This guide demonstrates how to integrate Evrmore Authentication into a FastAPI application. FastAPI is a modern, fast web framework for building APIs with Python that's well-suited for projects requiring blockchain authentication.

## Prerequisites

- Python 3.8+
- FastAPI and its dependencies (`pip3 install fastapi uvicorn`)
- `evrmore-authentication` package installed
- Basic understanding of FastAPI and asynchronous Python

## Project Setup

Create a new directory for your FastAPI project:

```bash
mkdir fastapi-evrmore-auth
cd fastapi-evrmore-auth
```

Create a virtual environment and install the required packages:

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install fastapi uvicorn evrmore-authentication python-multipart
```

## Basic FastAPI Integration

### 1. Create the Main Application

Create a file named `main.py` with the following content:

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
from typing import Optional

from evrmore_authentication import EvrmoreAuth

# Initialize FastAPI app
app = FastAPI(title="Evrmore Auth API", description="API with Evrmore Authentication")

# Add CORS middleware to allow frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Evrmore Authentication
auth = EvrmoreAuth(
    jwt_secret="your-secret-key",  # Use a secure secret in production
    debug=True  # Set to False in production
)

# Create a Pydantic model for authentication requests
class AuthRequest(BaseModel):
    evrmore_address: str
    challenge: Optional[str] = None
    signature: Optional[str] = None

# Create a Pydantic model for token validation
class TokenRequest(BaseModel):
    token: str

@app.get("/")
async def read_root():
    return {"message": "Welcome to Evrmore Authentication API"}
```

### 2. Add Challenge Generation Endpoint

Add a challenge generation endpoint to the `main.py` file:

```python
@app.post("/generate-challenge")
async def generate_challenge(request: AuthRequest):
    """Generate a challenge for the provided Evrmore address"""
    try:
        challenge = auth.generate_challenge(request.evrmore_address)
        return {"status": "success", "challenge": challenge}
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(e)}
        )
```

### 3. Add Authentication Endpoint

Add an authentication endpoint to the `main.py` file:

```python
@app.post("/authenticate")
async def authenticate(request: AuthRequest):
    """Authenticate a user with their address, challenge, and signature"""
    try:
        session = auth.authenticate(
            evrmore_address=request.evrmore_address,
            challenge=request.challenge,
            signature=request.signature
        )
        
        return {
            "status": "success",
            "user_id": session.user_id,
            "token": session.token,
            "expires_at": str(session.expires_at)
        }
    except Exception as e:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": str(e)}
        )
```

### 4. Add Token Validation Endpoints

Add token validation endpoints to the `main.py` file:

```python
@app.post("/validate-token")
async def validate_token(request: TokenRequest):
    """Validate a JWT token"""
    token_data = auth.validate_token(request.token)
    
    if token_data:
        return {
            "status": "success",
            "user_id": token_data.get("sub"),
            "evrmore_address": token_data.get("evr_address")
        }
    else:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": "Invalid token"}
        )

@app.post("/logout")
async def logout(request: TokenRequest):
    """Invalidate a JWT token (logout)"""
    success = auth.invalidate_token(request.token)
    
    if success:
        return {"status": "success", "message": "Logged out successfully"}
    else:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Failed to log out"}
        )
```

### 5. Add Protected Routes with Authentication Dependency

Create authentication dependencies and protected routes:

```python
# Authentication dependency
async def get_current_user(request: Request):
    # Get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = auth_header.replace("Bearer ", "")
    token_data = auth.validate_token(token)
    
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Get the user by ID
    user_id = token_data.get("sub")
    user = auth.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Protected route example
@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    """This endpoint requires authentication"""
    return {
        "status": "success",
        "message": "You have access to this protected resource",
        "user_id": user.id,
        "evrmore_address": user.evrmore_address
    }
```

### 6. Run the Application

Add a main block to run the application:

```python
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
```

## Complete Example

The complete `main.py` file should look like this:

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
from typing import Optional

from evrmore_authentication import EvrmoreAuth

# Initialize FastAPI app
app = FastAPI(title="Evrmore Auth API", description="API with Evrmore Authentication")

# Add CORS middleware to allow frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Evrmore Authentication
auth = EvrmoreAuth(
    jwt_secret="your-secret-key",  # Use a secure secret in production
    debug=True  # Set to False in production
)

# Create a Pydantic model for authentication requests
class AuthRequest(BaseModel):
    evrmore_address: str
    challenge: Optional[str] = None
    signature: Optional[str] = None

# Create a Pydantic model for token validation
class TokenRequest(BaseModel):
    token: str

@app.get("/")
async def read_root():
    return {"message": "Welcome to Evrmore Authentication API"}

@app.post("/generate-challenge")
async def generate_challenge(request: AuthRequest):
    """Generate a challenge for the provided Evrmore address"""
    try:
        challenge = auth.generate_challenge(request.evrmore_address)
        return {"status": "success", "challenge": challenge}
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(e)}
        )

@app.post("/authenticate")
async def authenticate(request: AuthRequest):
    """Authenticate a user with their address, challenge, and signature"""
    try:
        session = auth.authenticate(
            evrmore_address=request.evrmore_address,
            challenge=request.challenge,
            signature=request.signature
        )
        
        return {
            "status": "success",
            "user_id": session.user_id,
            "token": session.token,
            "expires_at": str(session.expires_at)
        }
    except Exception as e:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": str(e)}
        )

@app.post("/validate-token")
async def validate_token(request: TokenRequest):
    """Validate a JWT token"""
    token_data = auth.validate_token(request.token)
    
    if token_data:
        return {
            "status": "success",
            "user_id": token_data.get("sub"),
            "evrmore_address": token_data.get("evr_address")
        }
    else:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": "Invalid token"}
        )

@app.post("/logout")
async def logout(request: TokenRequest):
    """Invalidate a JWT token (logout)"""
    success = auth.invalidate_token(request.token)
    
    if success:
        return {"status": "success", "message": "Logged out successfully"}
    else:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Failed to log out"}
        )

# Authentication dependency
async def get_current_user(request: Request):
    # Get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = auth_header.replace("Bearer ", "")
    token_data = auth.validate_token(token)
    
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Get the user by ID
    user_id = token_data.get("sub")
    user = auth.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Protected route example
@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    """This endpoint requires authentication"""
    return {
        "status": "success",
        "message": "You have access to this protected resource",
        "user_id": user.id,
        "evrmore_address": user.evrmore_address
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
```

## Running the Application

Run the FastAPI application:

```bash
python3 main.py
```

The API will be available at `http://localhost:8000`.

## Testing with Swagger UI

FastAPI provides automatic interactive API documentation with Swagger UI. You can access it at `http://localhost:8000/docs`.

Using the Swagger UI, you can:

1. Try the `/generate-challenge` endpoint to get a challenge
2. Use your Evrmore wallet to sign the challenge (or use the development tools for testing)
3. Submit the signature to the `/authenticate` endpoint to get a token
4. Use the token to access the `/protected` endpoint

## Frontend Integration

To integrate this API with a frontend application, you can use the Swagger UI as a reference for the required API calls. Here's an example of how you might implement the authentication flow in a JavaScript frontend:

```javascript
// Example frontend code (JavaScript)
async function authenticate(evrmoreAddress) {
  // Step 1: Generate a challenge
  const challengeResponse = await fetch('/generate-challenge', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ evrmore_address: evrmoreAddress })
  });
  const challengeData = await challengeResponse.json();
  
  if (challengeData.status !== 'success') {
    throw new Error(challengeData.message);
  }
  
  // Step 2: Sign the challenge with the Evrmore wallet
  // This depends on your wallet integration
  const signature = await signWithWallet(evrmoreAddress, challengeData.challenge);
  
  // Step 3: Authenticate with the signature
  const authResponse = await fetch('/authenticate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      evrmore_address: evrmoreAddress,
      challenge: challengeData.challenge,
      signature: signature
    })
  });
  
  const authData = await authResponse.json();
  
  if (authData.status !== 'success') {
    throw new Error(authData.message);
  }
  
  // Store the token for future requests
  localStorage.setItem('authToken', authData.token);
  
  return authData;
}

// Example of how to make authenticated requests
async function fetchProtectedResource() {
  const token = localStorage.getItem('authToken');
  
  if (!token) {
    throw new Error('Not authenticated');
  }
  
  const response = await fetch('/protected', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  return await response.json();
}

// Example of how to log out
async function logout() {
  const token = localStorage.getItem('authToken');
  
  if (!token) {
    return { status: 'success', message: 'Already logged out' };
  }
  
  const response = await fetch('/logout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ token })
  });
  
  const data = await response.json();
  
  if (data.status === 'success') {
    localStorage.removeItem('authToken');
  }
  
  return data;
}
```

## Next Steps

After implementing this basic FastAPI integration, you can:

1. Add more protected routes and resources
2. Implement user profiles and additional user data
3. Add refresh token functionality
4. Integrate with a database for persistent storage
5. Add rate limiting and other security features
6. Implement OAuth 2.0 for third-party applications

For OAuth 2.0 integration, see the [OAuth client example](oauth-client.md) documentation. 