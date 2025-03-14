# Core Auth API Reference

This document provides detailed information about the core authentication API in the Evrmore Authentication system.

## Core Classes

### EvrmoreAuth

The `EvrmoreAuth` class is the main entry point for the authentication system. It provides methods for challenge generation, authentication, token validation, and more.

```python
from evrmore_authentication import EvrmoreAuth

# Initialize with default settings
auth = EvrmoreAuth()

# Initialize with custom settings
auth = EvrmoreAuth(
    jwt_secret="your-custom-secret",
    jwt_algorithm="HS256",
    jwt_private_key_path=None,
    jwt_public_key_path=None,
    jwt_issuer="custom-issuer",
    jwt_audience="custom-audience",
    access_token_expires=60,  # minutes
    refresh_token_expires=1440,  # minutes
    debug=False
)
```

### UserSession

The `UserSession` class represents an authenticated user session.

```python
@dataclass
class UserSession:
    user_id: str
    evrmore_address: str
    token: str
    expires_at: datetime.datetime
```

## Authentication Flow

### Challenge Generation

Generate a challenge for a user to sign with their Evrmore wallet.

```python
challenge = auth.generate_challenge(evrmore_address, expire_minutes=15)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `evrmore_address` | string | Yes | - | Evrmore wallet address |
| `expire_minutes` | integer | No | 15 | Challenge expiration time in minutes |

**Returns:**

A challenge string that the user needs to sign.

**Errors:**

- `ValidationError`: If the Evrmore address is invalid
- `RateLimitError`: If too many challenges have been generated for this address

### Authentication

Authenticate a user by verifying their signature against a challenge.

```python
session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge="Sign this message to authenticate: a8f7e9d1c2b3a4f5e6d7c8b9a1f2e3d4",
    signature="H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH...",
    token_expire_minutes=30,
    ip_address=None,
    user_agent=None,
    skip_ownership_check=False,
    scope="profile"
)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `evrmore_address` | string | Yes | - | Evrmore wallet address |
| `challenge` | string | Yes | - | The challenge text the user signed |
| `signature` | string | Yes | - | Base64-encoded signature of the challenge |
| `token_expire_minutes` | integer | No | 30 | Token expiration time in minutes |
| `ip_address` | string | No | None | IP address for the session |
| `user_agent` | string | No | None | User agent for the session |
| `skip_ownership_check` | boolean | No | False | Skip checking if the challenge belongs to this address |
| `scope` | string | No | "profile" | Requested scope for the token |

**Returns:**

A `UserSession` object containing the token and session information.

**Errors:**

- `ValidationError`: If the Evrmore address is invalid
- `ChallengeExpiredError`: If the challenge has expired
- `ChallengeUsedError`: If the challenge has already been used
- `InvalidSignatureError`: If the signature verification fails

### Token Validation

Validate a JWT token.

```python
token_data = auth.validate_token(token)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `token` | string | Yes | - | JWT token to validate |

**Returns:**

A dictionary containing the token claims if valid, or `None` if invalid.

**Example return value:**

```python
{
    "sub": "123e4567-e89b-12d3-a456-426614174000",  # User ID
    "evr_address": "EXaMPLeEvRMoReAddResS",
    "iat": 1614556800,  # Issued at timestamp
    "exp": 1614558600,  # Expiration timestamp
    "iss": "manticore-evrmore-auth",  # Issuer
    "aud": "manticore-clients"  # Audience
}
```

### Getting User by Token

Retrieve a user by their token.

```python
user = auth.get_user_by_token(token)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `token` | string | Yes | - | JWT token to validate |

**Returns:**

A `User` object if the token is valid, or raises an exception if invalid.

### Token Invalidation (Logout)

Invalidate a JWT token.

```python
auth.invalidate_token(token)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `token` | string | Yes | - | JWT token to invalidate |

**Returns:**

`True` if successful, `False` otherwise.

### Invalidate All User Tokens

Invalidate all tokens for a user.

```python
auth.invalidate_all_tokens(user_id)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `user_id` | string | Yes | - | User ID |

**Returns:**

`True` if successful, `False` otherwise.

## Signature Verification

### Verify Signature

Verify a signature against a message and address.

```python
is_valid = auth.verify_signature(
    address="EXaMPLeEvRMoReAddResS",
    message="Message to sign",
    signature="H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH...",
    run_hooks=True
)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `address` | string | Yes | - | Evrmore wallet address |
| `message` | string | Yes | - | Message that was signed |
| `signature` | string | Yes | - | Base64-encoded signature |
| `run_hooks` | boolean | No | True | Whether to run event hooks |

**Returns:**

`True` if the signature is valid, `False` otherwise.

### Verify Signature Only

Verify a signature without creating a challenge or user.

```python
is_valid = auth.verify_signature_only(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    message="Message to sign",
    signature="H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH..."
)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `evrmore_address` | string | Yes | - | Evrmore wallet address |
| `message` | string | Yes | - | Message that was signed |
| `signature` | string | Yes | - | Base64-encoded signature |

**Returns:**

`True` if the signature is valid, `False` otherwise.

## User Management

### Get User by ID

Retrieve a user by their ID.

```python
user = auth.get_user_by_id(user_id)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `user_id` | string | Yes | - | User ID |

**Returns:**

A `User` object if found, or `None` if not found.

### User Object

The `User` object represents a user in the system.

```python
@dataclass
class User:
    id: str
    evrmore_address: str
    username: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    last_login: Optional[datetime.datetime] = None
```

Key methods:

```python
# Create a new user
user = User.create(evrmore_address, username=None, email=None)

# Save user to database
user.save()

# Get user by ID
user = User.get_by_id(user_id)

# Get user by Evrmore address
user = User.get_by_address(evrmore_address)

# Convert user to dictionary
user_dict = user.to_dict()
```

## Challenge Management

### Get Challenge Details

Get details about a challenge.

```python
challenge = auth.get_challenge_details(challenge_text)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `challenge_text` | string | Yes | - | Challenge text |

**Returns:**

A `Challenge` object if found, or `None` if not found.

### Challenge Object

The `Challenge` object represents an authentication challenge.

```python
@dataclass
class Challenge:
    id: str
    user_id: str
    challenge_text: str
    expires_at: datetime.datetime
    used: bool = False
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
```

Key methods:

```python
# Check if challenge is expired
is_expired = challenge.is_expired

# Get challenge by ID
challenge = Challenge.get_by_id(challenge_id)

# Get challenge by text
challenge = Challenge.get_by_text(challenge_text)

# Get challenges for a user
challenges = Challenge.get_by_user_id(user_id)
```

### Create Manual Challenge

Create a challenge manually.

```python
challenge = auth.create_manual_challenge(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge_text=None,  # Generated if None
    expire_minutes=15
)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `evrmore_address` | string | Yes | - | Evrmore wallet address |
| `challenge_text` | string | No | None | Custom challenge text (generated if None) |
| `expire_minutes` | integer | No | 15 | Challenge expiration time in minutes |

**Returns:**

A string containing the challenge text.

### Reassign Challenge

Reassign a challenge to a different user or address.

```python
auth.reassign_challenge(
    challenge_text="Challenge text",
    new_user_id=None,
    new_address=None
)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `challenge_text` | string | Yes | - | Challenge text |
| `new_user_id` | string | No | None | New user ID |
| `new_address` | string | No | None | New Evrmore address |

**Returns:**

`True` if successful, `False` otherwise.

## Utility Methods

### Cleanup Expired Challenges

Remove expired challenges from the database.

```python
count = auth.cleanup_expired_challenges()
```

**Returns:**

The number of challenges removed.

### Cleanup Expired Sessions

Remove expired sessions from the database.

```python
count = auth.cleanup_expired_sessions()
```

**Returns:**

The number of sessions removed.

### Create Wallet Address

Create a new Evrmore wallet address.

```python
address, private_key = auth.create_wallet_address()
```

**Returns:**

A tuple containing the Evrmore address and private key.

### Sign Message

Sign a message with a private key.

```python
signature = auth.sign_message(wif_key, message)
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `wif_key` | string | Yes | - | Private key in WIF format |
| `message` | string | Yes | - | Message to sign |

**Returns:**

A base64-encoded signature.

## Error Handling

```python
from evrmore_authentication.exceptions import (
    AuthenticationError,
    ValidationError,
    ChallengeExpiredError,
    ChallengeUsedError,
    InvalidSignatureError,
    RateLimitError
)

try:
    session = auth.authenticate(evrmore_address, challenge, signature)
except ChallengeExpiredError:
    print("Challenge has expired")
except ChallengeUsedError:
    print("Challenge has already been used")
except InvalidSignatureError:
    print("Signature verification failed")
except ValidationError as e:
    print(f"Validation error: {str(e)}")
except AuthenticationError as e:
    print(f"Authentication error: {str(e)}")
``` 