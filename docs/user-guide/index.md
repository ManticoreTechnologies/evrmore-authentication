# User Guide

This guide explains how to use Evrmore Authentication in your applications.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Basic Usage](#basic-usage)
- [FastAPI Integration](#fastapi-integration)
- [Security Considerations](#security-considerations)

## Installation

```bash
pip3 install evrmore-authentication
```

## Configuration

Before using Evrmore Authentication, you need to configure both Evrmore RPC and your database connection.

### Environment Variables

Set the following environment variables:

```bash
# Evrmore RPC Configuration
export EVRMORE_RPC_URL=http://127.0.0.1:8819
export EVRMORE_RPC_USER=yourusername
export EVRMORE_RPC_PASSWORD=yourpassword

# SQLite Configuration
export SQLITE_DB_PATH=./data/evrmore_auth.db

# JWT Configuration
export JWT_SECRET=your-secure-secret-key
export JWT_ALGORITHM=HS256
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
export CHALLENGE_EXPIRE_MINUTES=10
```

### Database Initialization

Initialize the database tables:

```python
from evrmore_authentication.db import init_db

# Create all tables
init_db()
```

## Basic Usage

### Initializing the Authentication System

```python
from evrmore_authentication import EvrmoreAuth

# Create an authentication instance
auth = EvrmoreAuth()
```

### Authentication Flow

```python
# 1. Generate a challenge for a user
challenge = auth.generate_challenge(evrmore_address="EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW")

# 2. User signs the challenge with their wallet and sends the signature
signature = "user-provided-signature"

# 3. Authenticate the user and get a session
try:
    session = auth.authenticate(
        evrmore_address="EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW",
        challenge=challenge,
        signature=signature
    )
    
    # Use the session token for subsequent requests
    token = session.token
except InvalidSignatureError:
    # Handle invalid signature
    pass
except ChallengeExpiredError:
    # Handle expired challenge
    pass
```

### Validating User Sessions

```python
try:
    # Validate a JWT token
    payload = auth.validate_token(token)
    
    # Get the user associated with a token
    user = auth.get_user_by_token(token)
except InvalidTokenError:
    # Handle invalid token
    pass
```

## FastAPI Integration

The package provides built-in FastAPI integration:

```python
from fastapi import FastAPI, Depends, HTTPException
from evrmore_authentication import get_current_user

app = FastAPI()

@app.get("/protected-route")
async def protected_route(current_user = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.evrmore_address}!"}
```

## Security Considerations

### Atomicity

All database operations are atomic, meaning they are executed as a single transaction that either succeeds completely or fails completely. This prevents partial updates that could lead to security issues.

### Challenge Expiry

Challenges expire after a configurable time period (default: 10 minutes) to prevent replay attacks.

### One-Time Challenges

Each challenge can only be used once and is marked as used after successful authentication.

### JWT Best Practices

- Use a strong, unique `JWT_SECRET` in production
- Set a reasonable token expiry time
- Store tokens securely on the client side 