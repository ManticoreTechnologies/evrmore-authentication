# Evrmore Authentication API Reference

This document provides a detailed reference for all the classes, methods, and functions available in the Evrmore Authentication package.

## Table of Contents

- [EvrmoreAuth Class](#evrmoreauth-class)
- [UserSession Class](#usersession-class)
- [Database Models](#database-models)
- [Dependency Utilities](#dependency-utilities)
- [Exceptions](#exceptions)
- [CLI Commands](#cli-commands)
- [REST API Server](#rest-api-server)

## EvrmoreAuth Class

The main class that provides authentication functionality.

### Constructor

```python
EvrmoreAuth(db=None, jwt_secret=None, jwt_algorithm=None)
```

**Parameters:**
- `db` (Session, optional): SQLAlchemy session instance. If not provided, a new session is created.
- `jwt_secret` (str, optional): Secret key for JWT token generation. If not provided, it's taken from environment variables.
- `jwt_algorithm` (str, optional): Algorithm to use for JWT tokens. If not provided, it defaults to "HS256".

**Properties:**
- `evrmore_available` (bool): Indicates if the Evrmore node is available.

### Methods

#### generate_challenge

```python
generate_challenge(evrmore_address, expire_minutes=None)
```

Generates a unique challenge for a user to sign.

**Parameters:**
- `evrmore_address` (str): The Evrmore wallet address.
- `expire_minutes` (int, optional): Minutes until the challenge expires. Default from environment variable.

**Returns:**
- `str`: Challenge text to be signed by the user's wallet.

**Raises:**
- `AuthenticationError`: If there is an error generating the challenge.

#### authenticate

```python
authenticate(evrmore_address, challenge, signature, ip_address=None, user_agent=None, token_expire_minutes=None)
```

Authenticates a user using their signed challenge.

**Parameters:**
- `evrmore_address` (str): The Evrmore wallet address.
- `challenge` (str): The challenge text that was signed.
- `signature` (str): The signature created by signing the challenge.
- `ip_address` (str, optional): User's IP address.
- `user_agent` (str, optional): User's agent string.
- `token_expire_minutes` (int, optional): Minutes until token expires.

**Returns:**
- `UserSession`: Session data including the JWT token.

**Raises:**
- `UserNotFoundError`: If user with the address is not found.
- `ChallengeExpiredError`: If the challenge has expired.
- `ChallengeAlreadyUsedError`: If the challenge has already been used.
- `InvalidSignatureError`: If signature verification fails.
- `AuthenticationError`: For other authentication errors.

#### validate_token

```python
validate_token(token)
```

Validates a JWT token and returns the token payload.

**Parameters:**
- `token` (str): JWT token to validate.

**Returns:**
- `dict`: Token payload data.

**Raises:**
- `InvalidTokenError`: If the token is invalid or expired.
- `SessionExpiredError`: If the session has expired.

#### get_user_by_token

```python
get_user_by_token(token)
```

Gets a user by their token.

**Parameters:**
- `token` (str): JWT token to look up.

**Returns:**
- `User`: User object.

**Raises:**
- `InvalidTokenError`: If the token is invalid.
- `UserNotFoundError`: If the user is not found.

#### invalidate_token

```python
invalidate_token(token)
```

Invalidates a specific token (logout).

**Parameters:**
- `token` (str): JWT token to invalidate.

**Returns:**
- `bool`: True if token was invalidated successfully.

#### invalidate_all_tokens

```python
invalidate_all_tokens(user_id)
```

Invalidates all tokens for a specific user (logout from all devices).

**Parameters:**
- `user_id` (str): User ID to invalidate tokens for.

**Returns:**
- `int`: Number of tokens invalidated.

#### create_wallet_address

```python
create_wallet_address()
```

Creates a new Evrmore wallet address (for testing).

**Returns:**
- `str`: New Evrmore address.

**Raises:**
- `RuntimeError`: If the Evrmore node is not available.

#### sign_message

```python
sign_message(address, message)
```

Signs a message with an Evrmore wallet (for testing).

**Parameters:**
- `address` (str): Evrmore address to sign with.
- `message` (str): Message to sign.

**Returns:**
- `str`: Signature.

**Raises:**
- `RuntimeError`: If the Evrmore node is not available.

## UserSession Class

A dataclass that holds user session information.

```python
@dataclass
class UserSession:
    user_id: str
    evrmore_address: str
    token: str
    expires_at: datetime.datetime
```

## Database Models

### User

Represents an authenticated wallet owner.

**Fields:**
- `id` (UUID): Primary key.
- `evrmore_address` (String): Unique Evrmore address.
- `username` (String, optional): User's username.
- `email` (String, optional): User's email.
- `is_active` (Boolean): Whether the user is active.
- `created_at` (DateTime): When the user was created.
- `last_login` (DateTime, optional): When the user last logged in.

**Relationships:**
- `challenges`: One-to-many relationship with Challenge.
- `sessions`: One-to-many relationship with Session.

### Challenge

Stores authentication challenges.

**Fields:**
- `id` (UUID): Primary key.
- `user_id` (UUID): Foreign key to User.
- `challenge_text` (Text): The challenge text.
- `created_at` (DateTime): When the challenge was created.
- `expires_at` (DateTime): When the challenge expires.
- `used` (Boolean): Whether the challenge has been used.

**Properties:**
- `is_expired`: Whether the challenge has expired.

### Session

Stores user authentication sessions.

**Fields:**
- `id` (UUID): Primary key.
- `user_id` (UUID): Foreign key to User.
- `token` (String): JWT token.
- `token_id` (String): The JWT token ID.
- `created_at` (DateTime): When the session was created.
- `expires_at` (DateTime): When the session expires.
- `is_active` (Boolean): Whether the session is active.
- `ip_address` (String, optional): User's IP address.
- `user_agent` (String, optional): User's agent string.

**Properties:**
- `is_expired`: Whether the session has expired.

## Dependency Utilities

### get_current_user

```python
async def get_current_user(token: str)
```

FastAPI dependency for getting the current authenticated user.

**Parameters:**
- `token` (str): JWT token from HTTP Authorization header.

**Returns:**
- `User`: The current authenticated user.

**Raises:**
- `HTTPException`: If authentication fails.

## Exceptions

- `AuthenticationError`: Base class for all authentication errors.
- `UserNotFoundError`: Raised when a user with the given address is not found.
- `ChallengeExpiredError`: Raised when an authentication challenge has expired.
- `ChallengeAlreadyUsedError`: Raised when a challenge has already been used.
- `InvalidSignatureError`: Raised when the signature verification fails.
- `SessionExpiredError`: Raised when a session has expired.
- `InvalidTokenError`: Raised when a token is invalid or has been invalidated.
- `ConfigurationError`: Raised when there's a configuration error.

## CLI Commands

The `evrmore-auth` command-line tool provides the following commands:

### init

```bash
evrmore-auth init
```

Initialize the database by creating all tables.

### test

```bash
evrmore-auth test connection
```

Test the connection to the Evrmore node.

### user

```bash
evrmore-auth user list
evrmore-auth user create --address <address> [--username <username>] [--email <email>]
evrmore-auth user update --id <user_id> [--username <username>] [--email <email>] [--active <active>]
evrmore-auth user delete --id <user_id>
```

User management commands.

### session

```bash
evrmore-auth session list [--user-id <user_id>]
evrmore-auth session revoke --id <session_id>
evrmore-auth session revoke-all --user-id <user_id>
```

Session management commands.

## REST API Server

Evrmore Authentication includes a standalone REST API server that can be used to provide authentication services via HTTP endpoints. This is particularly useful for microservice architectures or when integrating with non-Python applications.

### Running the API Server

The API server can be run using the `evrmore-auth-api` command-line tool:

```bash
# Start the API server on port 8000
evrmore-auth-api

# Start with specific host and port
evrmore-auth-api --host 127.0.0.1 --port 9000

# Enable development mode with auto-reload
evrmore-auth-api --reload

# Change log level
evrmore-auth-api --log-level debug

# Run with multiple workers
evrmore-auth-api --workers 4
```

### API Endpoints

The REST API provides the following endpoints:

#### Authentication Endpoints

##### POST /challenge

Generate a challenge for a user to sign with their Evrmore wallet.

**Request Body:**
```json
{
  "evrmore_address": "EVRxxxYourEvrmoreAddressxxx",
  "expire_minutes": 15  // Optional
}
```

**Response:**
```json
{
  "challenge": "Sign this message to authenticate: abc123...",
  "expires_at": "2023-03-14T12:34:56.789Z",
  "expires_in_minutes": 15
}
```

##### POST /authenticate

Authenticate a user using their signed challenge.

**Request Body:**
```json
{
  "evrmore_address": "EVRxxxYourEvrmoreAddressxxx",
  "challenge": "Sign this message to authenticate: abc123...",
  "signature": "xxxxSignaturexxxx",
  "token_expire_minutes": 30  // Optional
}
```

**Response:**
```json
{
  "token": "eyJhbGci...",
  "user_id": "12345abc-...",
  "evrmore_address": "EVRxxxYourEvrmoreAddressxxx",
  "expires_at": "2023-03-14T13:34:56.789Z"
}
```

##### POST /logout

Invalidate a JWT token (logout).

**Request Body:**
```json
{
  "token": "eyJhbGci..."
}
```

**Response:**
```json
{
  "success": true
}
```

#### Token Management Endpoints

##### GET /validate?token=eyJhbGci...

Validate a JWT token and return its payload if valid.

**Response (valid token):**
```json
{
  "valid": true,
  "user_id": "12345abc-...",
  "evrmore_address": "EVRxxxYourEvrmoreAddressxxx",
  "expires_at": "2023-03-14T13:34:56.789Z"
}
```

**Response (invalid token):**
```json
{
  "valid": false
}
```

#### User Endpoints

##### GET /me

Get information about the currently authenticated user.

**Headers:**
```
Authorization: Bearer eyJhbGci...
```

**Response:**
```json
{
  "id": "12345abc-...",
  "evrmore_address": "EVRxxxYourEvrmoreAddressxxx",
  "username": "username",  // Optional
  "email": "user@example.com",  // Optional
  "is_active": true,
  "created_at": "2023-03-13T12:34:56.789Z",
  "last_login": "2023-03-14T12:34:56.789Z"  // Optional
}
```

### Integrating with Other Services

You can integrate the Evrmore Authentication API with any service that can make HTTP requests:

#### Using JavaScript/Fetch API

```javascript
// Generate a challenge
async function generateChallenge(evrmoreAddress) {
  const response = await fetch('http://auth-api:8000/challenge', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ evrmore_address: evrmoreAddress })
  });
  return response.json();
}

// Authenticate with a signature
async function authenticate(evrmoreAddress, challenge, signature) {
  const response = await fetch('http://auth-api:8000/authenticate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      evrmore_address: evrmoreAddress,
      challenge: challenge,
      signature: signature
    })
  });
  return response.json();
}
```

#### Using Python/Requests

```python
import requests

# Generate a challenge
def generate_challenge(evrmore_address):
    response = requests.post(
        "http://auth-api:8000/challenge",
        json={"evrmore_address": evrmore_address}
    )
    return response.json()

# Authenticate with a signature
def authenticate(evrmore_address, challenge, signature):
    response = requests.post(
        "http://auth-api:8000/authenticate",
        json={
            "evrmore_address": evrmore_address,
            "challenge": challenge,
            "signature": signature
        }
    )
    return response.json()
```

### Docker Deployment

The API server can be easily deployed using Docker:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY . .
RUN pip3 install -e .

EXPOSE 8000

CMD ["evrmore-auth-api", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:

```bash
docker build -t evrmore-auth-api .
docker run -p 8000:8000 -v $(pwd)/.env:/app/.env evrmore-auth-api
```

#### Using Docker Compose

For a more complete deployment including a database, use the provided `docker-compose.yml`:

```bash
# Copy the example .env file and adjust it
cp .env.example .env

# Start the services
docker-compose up -d

# Check logs
docker-compose logs -f auth-api

# Stop the services
docker-compose down
```

The Docker Compose setup includes:
- The Evrmore Authentication API server
- A PostgreSQL database (optional, can use SQLite instead)
- Proper networking between services
- Volume mounts for persistent data

You can customize the deployment by editing the `.env` file and `docker-compose.yml` file. 