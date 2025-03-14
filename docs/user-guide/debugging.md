# Debugging Guide & Advanced Features

This guide explains how to use the advanced features and debugging capabilities of Evrmore Authentication.

## Debugging Mode

Evrmore Authentication includes a detailed debug mode that can help you troubleshoot issues:

### Enabling Debug Mode

You can enable debug mode in several ways:

1. **Environment Variable**:
   ```bash
   export EVRMORE_AUTH_DEBUG=true
   ```

2. **Direct Initialization**:
   ```python
   from evrmore_authentication import EvrmoreAuth
   auth = EvrmoreAuth(debug=True)
   ```

When debug mode is enabled, detailed logging will show:
- Challenge generation steps
- Challenge ownership details
- Signature verification attempts
- Database operations
- Hook execution details

## Utility Scripts

Evrmore Authentication comes with several utility scripts to help you manage the system:

### Database Management

The `db_manage.py` script provides tools to manage your database:

```bash
# Initialize the database
./scripts/db_manage.py init

# Show database information
./scripts/db_manage.py info

# List users
./scripts/db_manage.py list-users

# List challenges
./scripts/db_manage.py list-challenges

# List sessions
./scripts/db_manage.py list-sessions

# Clean up expired records
./scripts/db_manage.py cleanup

# Check database integrity
./scripts/db_manage.py check-integrity
```

### Managing Challenges

You can view, create, and reassign challenges:

```bash
# List challenges for a specific address
./scripts/db_manage.py list-challenges -a "EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW"

# Create a challenge for an address
./scripts/db_manage.py create-challenge "EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW"

# Reassign a challenge to a different address
./scripts/db_manage.py reassign "Sign this message..." "ENewAddressHere"
```

### Signature Verification

The `verify_signature.py` script allows you to verify signatures without database interaction:

```bash
# Verify a signature
./scripts/verify_signature.py verify "EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW" "message to verify" "signature"

# Generate a challenge format
./scripts/verify_signature.py challenge "EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW"
```

## Event Hooks

Evrmore Authentication supports event hooks that let you customize the authentication flow:

```python
from evrmore_authentication import EvrmoreAuth

auth = EvrmoreAuth()

# Add a hook to run before challenge generation
def pre_challenge_hook(address, expire_minutes):
    print(f"Generating challenge for {address}")
    return {"custom_data": "value"}
    
auth.add_hook('pre_challenge', pre_challenge_hook)

# Available hook points:
# - pre_challenge: Before generating a challenge
# - post_challenge: After generating a challenge
# - pre_auth: Before authenticating a user
# - post_auth: After successful authentication
# - pre_verify: Before verifying a signature
# - post_verify: After verifying a signature
```

## Advanced Authentication Options

### Skip Ownership Checks

When authenticating, you can skip the challenge ownership check:

```python
session = auth.authenticate(
    evrmore_address="EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW",
    challenge=challenge_text,
    signature=signature,
    skip_ownership_check=True  # Skip the ownership check
)
```

This is useful when:
- You're migrating users from another system
- You want to manually verify challenges
- You're using a custom challenge format

### Direct Signature Verification

You can verify signatures directly without challenge management:

```python
# Just verify the signature
is_valid = auth.verify_signature_only(
    address="EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW",
    message="message to verify",
    signature="signature"
)
```

### Challenge Management

You can manually manage challenges using these methods:

```python
# Get information about a challenge
challenge_info = auth.get_challenge_details(challenge_text)

# Reassign a challenge to a different user
auth.reassign_challenge(
    challenge_text="challenge_text", 
    new_address="EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW"
)

# Create a manual challenge
challenge = auth.create_manual_challenge(
    evrmore_address="EY8NRvv83BYMXSDf5DJYCmZQAhaMzZLWgW",
    challenge_text="custom challenge text"  # Optional
)
```

## Database Maintenance

### Clean Up Expired Records

You can clean up expired records programmatically:

```python
# Clean up expired challenges
expired_challenges = auth.cleanup_expired_challenges()
print(f"Removed {expired_challenges} expired challenges")

# Clean up expired sessions
expired_sessions = auth.cleanup_expired_sessions()
print(f"Removed {expired_sessions} expired sessions")
```

## Troubleshooting Common Issues

### Challenge Ownership Errors

If you encounter "Challenge does not belong to this user" errors:

1. Check if the challenge was generated for a different address:

```bash
./scripts/db_manage.py list-challenges -a "correct-address"
```

2. Reassign the challenge to the correct user:

```bash
./scripts/db_manage.py reassign "challenge text" "correct-address"
```

Or programmatically:

```python
auth.reassign_challenge(challenge_text, new_address="correct-address")
```

### Signature Verification Failures

If signature verification fails:

1. Verify the signature format using the verification tool:

```bash
./scripts/verify_signature.py verify "address" "message" "signature"
```

2. Check if your wallet is using a different message format. Try these options in your code:

```python
# Option 1: Skip ownership checks
session = auth.authenticate(
    evrmore_address=address,
    challenge=challenge,
    signature=signature,
    skip_ownership_check=True
)

# Option 2: Add a custom verification hook
def custom_verify_hook(address, message, signature):
    # Custom verification logic
    return True  # or False

auth.add_hook('pre_verify', custom_verify_hook)
``` 