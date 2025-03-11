# Evrmore Authentication

[![PyPI version](https://badge.fury.io/py/evrmore-authentication.svg)](https://badge.fury.io/py/evrmore-authentication)
[![Documentation Status](https://readthedocs.io/en/latest/?badge=latest)](https://evrmore-authentication.readthedocs.io/en/latest/?badge=latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust and secure authentication system that leverages Evrmore blockchain signatures for user authentication and session management.

## Features

- **Blockchain-based Authentication**: Uses Evrmore wallet signatures for secure user authentication
- **Challenge-Response Protocol**: Generates unique challenges for each authentication attempt
- **PostgreSQL Integration**: Stores user data and session information in a PostgreSQL database
- **Atomic Operations**: Ensures transaction integrity with database-level atomicity
- **JWT Support**: Issues and validates JSON Web Tokens for authenticated sessions
- **Modern Auth Workflows**: Supports standard OAuth2 flows
- **Comprehensive Security**: Protection against common attack vectors

## Installation

```bash
pip3 install evrmore-authentication
```

## Configuration

Create a configuration file (`.env` or similar):

```
# Evrmore RPC Configuration
EVRMORE_RPC_HOST=localhost
EVRMORE_RPC_PORT=8819
EVRMORE_RPC_USER=yourusername
EVRMORE_RPC_PASSWORD=yourpassword

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=evrmore_auth
DB_USER=postgres
DB_PASSWORD=yourdbpassword

# JWT Configuration
JWT_SECRET=your-secure-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
```

If no RPC credentials are provided, the library will automatically try to use the default evrmore.conf file location.

## Quick Start

### Set up the database

```python
from evrmore_authentication.db import init_db

init_db()
```

### Basic Authentication Flow

```python
from evrmore_authentication import EvrmoreAuth

# Initialize the auth system
auth = EvrmoreAuth()

# Generate a challenge for a user
challenge = auth.generate_challenge(evrmore_address="EXaMPLeEvRMoReAddResS")

# On the client side, the user would sign this challenge with their wallet
# When the signed message is received:
signed_message = "user_signed_message_from_wallet"

# Verify the signature and create a session
user_session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature=signed_message
)

# Use the session token for subsequent requests
token = user_session.token
```

### In a FastAPI Application

```python
from fastapi import FastAPI, Depends, HTTPException
from evrmore_authentication import EvrmoreAuth, get_current_user

app = FastAPI()
auth = EvrmoreAuth()

@app.post("/auth/challenge")
async def get_challenge(evrmore_address: str):
    challenge = auth.generate_challenge(evrmore_address=evrmore_address)
    return {"challenge": challenge}

@app.post("/auth/login")
async def login(evrmore_address: str, challenge: str, signature: str):
    try:
        session = auth.authenticate(
            evrmore_address=evrmore_address,
            challenge=challenge,
            signature=signature
        )
        return {"access_token": session.token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/users/me")
async def read_users_me(current_user = Depends(get_current_user)):
    return current_user
```

## Documentation

For full documentation, visit [https://manticoretechnologies.github.io/evrmore-authentication/](https://manticoretechnologies.github.io/evrmore-authentication/)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Copyright

© 2023 Manticore Technologies - [manticore.technology](https://manticore.technology) 