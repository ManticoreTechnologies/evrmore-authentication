# Evrmore Authentication Developer Guide

## Overview

Evrmore Authentication is a Python package that provides secure user authentication using Evrmore blockchain wallet signatures. This guide explains how to integrate and use the package in your applications.

## How It Works

The authentication process follows these steps:

1. **Challenge Generation**: The server generates a unique challenge string for a user's Evrmore wallet address.
2. **User Signing**: The user signs the challenge with their Evrmore wallet.
3. **Signature Verification**: The server verifies the signature using Evrmore's `verifymessage` RPC.
4. **Session Creation**: Upon successful verification, the server creates a session and issues a JWT token.
5. **Authenticated Requests**: The user includes the JWT token in subsequent requests.

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

# Database Configuration
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=evrmore_auth
export DB_USER=postgres
export DB_PASSWORD=yourdbpassword

# JWT Configuration
export JWT_SECRET=your-secure-secret-key
export JWT_ALGORITHM=HS256
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Database Initialization

Initialize the database tables:

```python
from evrmore_authentication.db import init_db

# Create all tables
init_db()
```

Alternatively, you can use the CLI tool:

```bash
evrmore-auth init
```

### Using Alembic for Migrations

The package includes Alembic for database migrations:

```bash
# Generate a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback a migration
alembic downgrade -1
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

## Integration with Web Frameworks

### FastAPI Integration

The package provides built-in FastAPI integration:

```python
from fastapi import FastAPI, Depends, HTTPException
from evrmore_authentication import get_current_user

app = FastAPI()

@app.get("/protected-route")
async def protected_route(current_user = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.evrmore_address}!"}
```

See the `examples/fastapi_example.py` file for a complete FastAPI example.

## Command-Line Interface

The package includes a CLI tool for management tasks:

```bash
# Initialize the database
evrmore-auth init

# List users
evrmore-auth user list

# Create a user
evrmore-auth user create --address EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW --username john

# List active sessions
evrmore-auth session list

# Revoke a session
evrmore-auth session revoke --id session-uuid

# Test Evrmore RPC connection
evrmore-auth test connection
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

## Advanced Usage

### Custom Database Sessions

You can provide your own database session to the authentication system:

```python
from sqlalchemy.orm import Session
from evrmore_authentication import EvrmoreAuth

def with_custom_db_session(db_session: Session):
    auth = EvrmoreAuth(db=db_session)
    # Use auth with the custom session
```

### User Management

```python
# Get user by token
user = auth.get_user_by_token(token)

# Invalidate a specific token (logout)
auth.invalidate_token(token)

# Invalidate all tokens for a user (logout from all devices)
auth.invalidate_all_tokens(user.id)
```

## Troubleshooting

### RPC Connection Issues

If you encounter RPC connection issues:

1. Verify the Evrmore node is running
2. Check the RPC credentials are correct
3. Ensure the RPC port is accessible
4. Test the connection using `evrmore-auth test connection`

### Database Issues

For database connection issues:

1. Verify PostgreSQL is running
2. Check the database credentials
3. Ensure the database exists
4. Run migrations with `alembic upgrade head`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request on GitHub.

## License

MIT License

## Support

For support, please contact dev@manticore.technology or open an issue on GitHub. 