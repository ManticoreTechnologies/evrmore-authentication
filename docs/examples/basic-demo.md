# Basic Authentication Demo

This guide demonstrates a simple implementation of Evrmore Authentication in a basic Python application. It will walk you through implementing wallet-based authentication with minimal dependencies.

## Prerequisites

- Python 3.8+
- `evrmore-authentication` package installed
- Basic understanding of Python and Evrmore wallets

## Installation

```bash
pip3 install evrmore-authentication
```

## Simple Authentication Flow

### 1. Initialize the Authentication System

Create a simple script that initializes the Evrmore Authentication system:

```python
# auth_demo.py
from evrmore_authentication import EvrmoreAuth

# Initialize the authentication system
auth = EvrmoreAuth(
    jwt_secret="your-secret-key",
    debug=True  # Set to False in production
)

print("Evrmore Authentication system initialized")
```

### 2. Generate a Challenge

Add code to generate a challenge for a user to sign:

```python
# Generate a challenge for an Evrmore address
evrmore_address = "EXaMPLeEvRMoReAddResS"  # Replace with a real address
challenge = auth.generate_challenge(evrmore_address)

print(f"Challenge generated for {evrmore_address}:")
print(challenge)
```

### 3. Sign the Challenge with a Wallet

In a real application, the user would sign this challenge with their Evrmore wallet. For demonstration purposes, we'll use the development utilities to create a wallet and sign the challenge:

```python
# For demonstration purposes only - in a real app, user would sign with their wallet
from evrmore_authentication.crypto import create_wallet, sign_message

# Create a test wallet (in a real app, the user would use their own wallet)
address, private_key_wif = create_wallet()
print(f"Test wallet created: {address}")

# Sign the challenge
signature = sign_message(private_key_wif, challenge)
print(f"Signature: {signature}")
```

### 4. Authenticate with the Signature

Now authenticate the user with the signature:

```python
# Authenticate the user
try:
    session = auth.authenticate(
        evrmore_address=address,
        challenge=challenge,
        signature=signature
    )
    print("Authentication successful!")
    print(f"User ID: {session.user_id}")
    print(f"Token: {session.token}")
    print(f"Expires at: {session.expires_at}")
except Exception as e:
    print(f"Authentication failed: {str(e)}")
```

### 5. Validate the Token

Add code to validate the token:

```python
# Validate the token
token = session.token
token_data = auth.validate_token(token)

if token_data:
    print("Token is valid!")
    print(f"User ID: {token_data.get('sub')}")
    print(f"Evrmore Address: {token_data.get('evr_address')}")
else:
    print("Token is invalid!")
```

### 6. Invalidate the Token (Logout)

Finally, add code to invalidate the token (logout):

```python
# Invalidate the token (logout)
success = auth.invalidate_token(token)
if success:
    print("User logged out successfully")
else:
    print("Failed to log out")

# Try to validate the token again
token_data = auth.validate_token(token)
if token_data:
    print("Token is still valid (unexpected)")
else:
    print("Token has been invalidated")
```

## Complete Example

Here's the complete script:

```python
# auth_demo.py
from evrmore_authentication import EvrmoreAuth
from evrmore_authentication.crypto import create_wallet, sign_message

# Initialize the authentication system
auth = EvrmoreAuth(
    jwt_secret="your-secret-key",
    debug=True  # Set to False in production
)

print("Evrmore Authentication system initialized")

# Create a test wallet (in a real app, the user would use their own wallet)
address, private_key_wif = create_wallet()
print(f"Test wallet created: {address}")

# Generate a challenge for the address
challenge = auth.generate_challenge(address)
print(f"Challenge generated: {challenge}")

# Sign the challenge
signature = sign_message(private_key_wif, challenge)
print(f"Signature: {signature}")

# Authenticate the user
try:
    session = auth.authenticate(
        evrmore_address=address,
        challenge=challenge,
        signature=signature
    )
    print("Authentication successful!")
    print(f"User ID: {session.user_id}")
    print(f"Token: {session.token}")
    print(f"Expires at: {session.expires_at}")
except Exception as e:
    print(f"Authentication failed: {str(e)}")
    exit(1)

# Validate the token
token = session.token
token_data = auth.validate_token(token)

if token_data:
    print("Token is valid!")
    print(f"User ID: {token_data.get('sub')}")
    print(f"Evrmore Address: {token_data.get('evr_address')}")
else:
    print("Token is invalid!")

# Invalidate the token (logout)
success = auth.invalidate_token(token)
if success:
    print("User logged out successfully")
else:
    print("Failed to log out")

# Try to validate the token again
token_data = auth.validate_token(token)
if token_data:
    print("Token is still valid (unexpected)")
else:
    print("Token has been invalidated")
```

## Running the Demo

Save the script and run it:

```bash
python3 auth_demo.py
```

You should see output similar to this:

```
Evrmore Authentication system initialized
Test wallet created: EXaMPLeEvRMoReAddResS
Challenge generated: Sign this message to authenticate: a8f7e9d1c2b3...
Signature: H9LJFkR+a0MFm1jSvmoBZ1wQobuSGP...
Authentication successful!
User ID: 123e4567-e89b-12d3-a456-426614174000
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Expires at: 2023-03-16 15:30:45.123456
Token is valid!
User ID: 123e4567-e89b-12d3-a456-426614174000
Evrmore Address: EXaMPLeEvRMoReAddResS
User logged out successfully
Token has been invalidated
```

## Next Steps

After mastering this basic implementation, you can:

1. Integrate the authentication system into a web application
2. Add user profile management
3. Implement more advanced features like token refresh
4. Check out the FastAPI integration example for a more complete implementation

See the [FastAPI integration example](fastapi-integration.md) and [OAuth client example](oauth-client.md) for more advanced implementations. 