# API Reference

This document provides a detailed reference for all the classes, methods, and functions available in the Evrmore Authentication package.

## Table of Contents

- [EvrmoreAuth Class](#evrmoreauth-class)
- [UserSession Class](#usersession-class)
- [Database Models](#database-models)
- [Dependency Utilities](#dependency-utilities)
- [Exceptions](#exceptions)
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

### Challenge

Stores authentication challenges.

**Fields:**
- `id` (UUID): Primary key.
- `user_id` (UUID): Foreign key to User.
- `challenge_text` (Text): The challenge text.
- `created_at` (DateTime): When the challenge was created.
- `expires_at` (DateTime): When the challenge expires.
- `used` (Boolean): Whether the challenge has been used.

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

## REST API Server

Evrmore Authentication includes a standalone REST API server that can be used to provide authentication services via HTTP endpoints.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenge` | POST | Generate a challenge for a user |
| `/authenticate` | POST | Authenticate with a signed challenge |
| `/validate` | GET | Validate a JWT token |
| `/me` | GET | Get authenticated user information |
| `/logout` | POST | Invalidate a JWT token (logout) 