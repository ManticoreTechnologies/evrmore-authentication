# Event Hooks

The Event Hooks system in Evrmore Authentication allows you to add custom behavior at key points in the authentication flow. This enables you to extend functionality, add logging, integrate with other systems, or implement custom business logic.

## Overview

Event hooks are implemented as callback functions that are executed at specific points in the authentication process. You can register hooks for various events and they will be called with relevant context information when those events occur.

## Available Hook Points

The following hook points are available:

| Hook Point | Description | Triggered When |
|------------|-------------|----------------|
| `pre_challenge` | Before generating a challenge | `generate_challenge()` is called |
| `post_challenge` | After generating a challenge | A challenge has been created |
| `pre_auth` | Before authenticating a user | `authenticate()` is called |
| `post_auth` | After successful authentication | Authentication succeeds |
| `pre_verify` | Before verifying a signature | Signature verification begins |
| `post_verify` | After verifying a signature | Signature verification completes |
| `pre_token_validate` | Before validating a token | `validate_token()` is called |
| `post_token_validate` | After validating a token | Token validation completes |
| `pre_token_invalidate` | Before invalidating a token | `invalidate_token()` is called |
| `post_token_invalidate` | After invalidating a token | Token invalidation completes |

## Registering Hooks

Hooks can be registered using the `add_hook` method or as a decorator:

### Using the Method

```python
from evrmore_authentication import EvrmoreAuth

auth = EvrmoreAuth()

def my_pre_challenge_hook(evrmore_address, expire_minutes):
    print(f"Generating challenge for {evrmore_address}")
    return {"custom_data": "value"}  # Optional return value

# Register the hook
auth.add_hook('pre_challenge', my_pre_challenge_hook)
```

### Using the Decorator

```python
from evrmore_authentication import EvrmoreAuth

auth = EvrmoreAuth()

@auth.add_hook('post_auth')
def post_auth_hook(user, session):
    print(f"User {user.evrmore_address} authenticated successfully")
    # Perform custom actions after authentication
    notify_login(user.id)
```

## Hook Parameters

Each hook receives specific parameters relevant to its context:

### `pre_challenge`

```python
@auth.add_hook('pre_challenge')
def pre_challenge_hook(evrmore_address, expire_minutes):
    """
    evrmore_address: The address for which the challenge is being generated
    expire_minutes: The expiration time in minutes
    
    Return value: Can return a dict to modify parameters
    """
    # Can modify expire_minutes
    return {"expire_minutes": 30}
```

### `post_challenge`

```python
@auth.add_hook('post_challenge')
def post_challenge_hook(evrmore_address, challenge, challenge_record):
    """
    evrmore_address: The address for which the challenge was generated
    challenge: The challenge text
    challenge_record: The Challenge object created
    """
    # No return value expected
```

### `pre_auth`

```python
@auth.add_hook('pre_auth')
def pre_auth_hook(evrmore_address, challenge, signature, skip_ownership_check):
    """
    evrmore_address: The address being authenticated
    challenge: The challenge text
    signature: The signature to verify
    skip_ownership_check: Whether to skip challenge ownership verification
    
    Return value: Can return a dict to modify parameters
    """
    return {"skip_ownership_check": True}
```

### `post_auth`

```python
@auth.add_hook('post_auth')
def post_auth_hook(user, session):
    """
    user: The User object for the authenticated user
    session: The Session object created
    """
    # No return value expected
```

### `pre_verify`

```python
@auth.add_hook('pre_verify')
def pre_verify_hook(address, message, signature):
    """
    address: The Evrmore address
    message: The message (challenge) to verify
    signature: The signature to verify
    
    Return value: Can return a dict to modify parameters
    """
    # Can modify verification parameters
    return {"message": modified_message}
```

### `post_verify`

```python
@auth.add_hook('post_verify')
def post_verify_hook(address, message, signature, is_valid):
    """
    address: The Evrmore address
    message: The message that was verified
    signature: The signature that was verified
    is_valid: Boolean indicating if the signature was valid
    """
    # No return value expected
```

### `pre_token_validate`

```python
@auth.add_hook('pre_token_validate')
def pre_token_validate_hook(token):
    """
    token: The token to validate
    
    Return value: Can return a dict to modify parameters
    """
    # No modifications typically needed
    return {}
```

### `post_token_validate`

```python
@auth.add_hook('post_token_validate')
def post_token_validate_hook(token, token_data, is_valid):
    """
    token: The token that was validated
    token_data: The decoded token data if valid, None otherwise
    is_valid: Boolean indicating if the token was valid
    """
    # No return value expected
```

### `pre_token_invalidate`

```python
@auth.add_hook('pre_token_invalidate')
def pre_token_invalidate_hook(token):
    """
    token: The token to invalidate
    
    Return value: Can return a dict to modify parameters
    """
    # No modifications typically needed
    return {}
```

### `post_token_invalidate`

```python
@auth.add_hook('post_token_invalidate')
def post_token_invalidate_hook(token, session):
    """
    token: The token that was invalidated
    session: The Session object that was invalidated
    """
    # No return value expected
```

## Multiple Hooks

You can register multiple hooks for the same event. They will be executed in the order they were registered:

```python
@auth.add_hook('post_auth')
def log_auth(user, session):
    print(f"User {user.evrmore_address} authenticated")

@auth.add_hook('post_auth')
def notify_auth(user, session):
    send_notification(user.id, "New login detected")
```

## Modifying Parameters

Hooks that run before an operation (`pre_*` hooks) can modify the parameters passed to the operation by returning a dictionary with the modified values:

```python
@auth.add_hook('pre_challenge')
def extend_challenge_expiry(evrmore_address, expire_minutes):
    if is_premium_user(evrmore_address):
        # Premium users get longer-lived challenges
        return {"expire_minutes": 60}
    return {}  # Return empty dict to keep default parameters
```

## Practical Examples

### Logging Authentication Attempts

```python
@auth.add_hook('pre_auth')
def log_auth_attempt(evrmore_address, challenge, signature, skip_ownership_check):
    print(f"Authentication attempt by {evrmore_address}")
    return {}

@auth.add_hook('post_auth')
def log_auth_success(user, session):
    print(f"Successful authentication by {user.evrmore_address}")
    
@auth.add_hook('post_verify')
def log_verification_result(address, message, signature, is_valid):
    if not is_valid:
        print(f"Failed signature verification for {address}")
```

### Custom User Management

```python
@auth.add_hook('post_auth')
def update_user_data(user, session):
    # Update last login time in a custom database
    db.execute(
        "UPDATE user_metadata SET last_login = ? WHERE user_id = ?",
        (datetime.datetime.utcnow().isoformat(), user.id)
    )
    
    # Count login attempts
    login_count = db.fetchone(
        "SELECT login_count FROM user_stats WHERE user_id = ?",
        (user.id,)
    )
    
    if login_count:
        db.execute(
            "UPDATE user_stats SET login_count = login_count + 1 WHERE user_id = ?",
            (user.id,)
        )
    else:
        db.execute(
            "INSERT INTO user_stats (user_id, login_count) VALUES (?, ?)",
            (user.id, 1)
        )
```

### Security Enhancements

```python
@auth.add_hook('pre_challenge')
def rate_limit_challenges(evrmore_address, expire_minutes):
    # Check if too many challenges have been generated recently
    count = db.fetchone(
        """SELECT COUNT(*) as count FROM challenges 
        WHERE evrmore_address = ? AND created_at > ?""",
        (evrmore_address, (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat())
    )
    
    if count and count['count'] > 5:
        raise Exception("Rate limit exceeded for challenge generation")
    
    return {}

@auth.add_hook('post_auth')
def check_suspicious_activity(user, session):
    # Check if the user has logged in from a new location
    # Implementation depends on how you track locations
    current_ip = get_request_ip()
    
    known_ips = db.fetchall(
        "SELECT ip_address FROM user_locations WHERE user_id = ?",
        (user.id,)
    )
    
    if current_ip not in [row['ip_address'] for row in known_ips]:
        # New location, store it and notify user
        db.execute(
            "INSERT INTO user_locations (user_id, ip_address, first_seen) VALUES (?, ?, ?)",
            (user.id, current_ip, datetime.datetime.utcnow().isoformat())
        )
        
        send_notification(user.id, f"New login from {get_location_from_ip(current_ip)}")
```

### Integration with External Systems

```python
@auth.add_hook('post_auth')
def sync_with_crm(user, session):
    # Update user in CRM system
    crm_api.update_user(
        user_id=user.id,
        evrmore_address=user.evrmore_address,
        last_login=datetime.datetime.utcnow().isoformat()
    )

@auth.add_hook('post_token_invalidate')
def update_activity_tracking(token, session):
    # Log user logout in analytics system
    analytics.track_event(
        session.user_id,
        'user_logout',
        {
            'session_duration': (datetime.datetime.utcnow() - session.created_at).total_seconds(),
            'session_id': session.id
        }
    )
```

## Error Handling

Errors in hooks are logged but do not interrupt the main authentication flow by default. To change this behavior, you can set the `propagate_hook_errors` parameter when initializing `EvrmoreAuth`:

```python
auth = EvrmoreAuth(propagate_hook_errors=True)
```

With this setting, any exception raised in a hook will be propagated to the caller.

## Testing Hooks

To test hooks, you may want to mock the authentication systems:

```python
from unittest.mock import patch, MagicMock

def test_post_auth_hook():
    auth = EvrmoreAuth()
    
    # Create a spy to check if the hook was called
    spy = MagicMock()
    
    @auth.add_hook('post_auth')
    def my_hook(user, session):
        spy(user.id, session.id)
    
    # Mock authenticate to avoid actual authentication
    with patch.object(auth, 'authenticate') as mock_auth:
        # Create mock user and session
        mock_user = MagicMock()
        mock_user.id = "123"
        mock_user.evrmore_address = "EXaMPLeEvRMoReAddResS"
        
        mock_session = MagicMock()
        mock_session.id = "456"
        mock_session.user_id = "123"
        
        # Make authenticate return our mock session
        mock_auth.return_value = mock_session
        
        # Call authenticate
        auth.authenticate(
            evrmore_address="EXaMPLeEvRMoReAddResS",
            challenge="test_challenge",
            signature="test_signature"
        )
        
        # Verify hook was called with correct parameters
        spy.assert_called_once_with("123", "456")
``` 