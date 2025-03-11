# Getting Started with Evrmore Authentication

This guide will help you set up and start using the Evrmore Authentication package in your projects.

## Prerequisites

- Python 3.6 or higher
- An Evrmore node for signature verification
- PostgreSQL (for production) or SQLite (for development/testing)

## Installation

1. Install the package:

```bash
pip3 install evrmore-authentication
```

For development, install from source:

```bash
git clone https://github.com/manticoretechnologies/evrmore-authentication.git
cd evrmore-authentication
pip3 install -e .
```

## Configuration

Set up the following environment variables (or use a `.env` file):

```bash
# Evrmore RPC Configuration
export EVRMORE_RPC_HOST=localhost
export EVRMORE_RPC_PORT=8819
export EVRMORE_RPC_USER=yourusername
export EVRMORE_RPC_PASSWORD=yourpassword

# Database Configuration (PostgreSQL)
export DB_TYPE=postgresql
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=evrmore_auth
export DB_USER=postgres
export DB_PASSWORD=yourpassword

# Or for SQLite
export DB_TYPE=sqlite
export SQLITE_DB_PATH=evrmore_auth.db

# JWT Configuration
export JWT_SECRET=your-secure-secret-key
export JWT_ALGORITHM=HS256
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
```

## Initialize the Database

```python
from evrmore_authentication.db import init_db

# Create all tables
init_db()
```

Alternatively, use alembic for migrations:

```bash
alembic upgrade head
```

## Basic Usage Example

```python
from evrmore_authentication import EvrmoreAuth

# Initialize the auth system
auth = EvrmoreAuth()

# Generate a challenge for a user
challenge = auth.generate_challenge(evrmore_address="EXaMPLeEvRMoReAddResS")

# User signs the challenge with their wallet
# When the signed message is received:
signature = "user_signed_message_from_wallet"

# Verify the signature and create a session
user_session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature=signature
)

# Use the session token for subsequent requests
token = user_session.token

# Validate a token
token_data = auth.validate_token(token)

# Get user from token
user = auth.get_user_by_token(token)
```

## Web Application Demo

Check out the complete web application example in the `/examples/web_auth_demo` directory:

```bash
cd examples/web_auth_demo
./run.sh
```

This will start a Flask application showing the authentication flow with a user-friendly interface.

## More Resources

- [API Documentation](docs/api.md)
- [Developer Guide](docs/guide.md)
- [FastAPI Integration](docs/guide.md#fastapi-integration)

## Support

For support, please contact dev@manticore.technology or open an issue on GitHub. 