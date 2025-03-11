# Evrmore Authentication System

A complete authentication system using Evrmore wallet signatures for web applications.

## Features

- **Wallet-Based Authentication**: Authenticate users using their Evrmore wallet signatures
- **Automatic User Creation**: Users are automatically created on first authentication
- **Flexible Signature Verification**: Works with various wallet implementations
- **Token-Based Sessions**: JWT tokens for user sessions
- **Redis Data Storage**: Fast, in-memory storage with persistence
- **Comprehensive Logging**: Detailed logs for troubleshooting

## Installation

```bash
# Clone the repository
git clone https://github.com/manticoretechnologies/evrmore-authentication.git
cd evrmore-authentication

# Install the package and dependencies
pip3 install -e .
```

## Requirements

- Python 3.6+
- Redis server
- Evrmore node with RPC enabled

## Environment Variables

The system can be configured using the following environment variables:

```
EVRMORE_RPC_HOST=localhost    # Evrmore node RPC host
EVRMORE_RPC_PORT=8819         # Evrmore node RPC port
EVRMORE_RPC_USER=             # Evrmore node RPC username
EVRMORE_RPC_PASSWORD=         # Evrmore node RPC password
JWT_SECRET=                   # Secret key for JWT tokens (auto-generated if not set)
JWT_ALGORITHM=HS256           # Algorithm for JWT tokens
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30  # Token expiration time in minutes
CHALLENGE_EXPIRE_MINUTES=10   # Challenge expiration time in minutes
REDIS_HOST=localhost          # Redis host
REDIS_PORT=6379               # Redis port
REDIS_PASSWORD=               # Redis password
REDIS_DB=0                    # Redis database number
REDIS_PREFIX=evrauth:         # Prefix for Redis keys
```

## Basic Usage

```python
from evrmore_authentication import EvrmoreAuth
from evrmore_rpc import EvrmoreClient

# Initialize client and auth
client = EvrmoreClient()
auth = EvrmoreAuth(client)

# Generate challenge for a wallet address
address = "EXAMPLExxxxxxxxxxxxxxxxxxxxxxxxxxx"
challenge = auth.generate_challenge(address)

# User signs challenge with their wallet
# signature = user_wallet.signmessage(address, challenge)

# Authenticate with the signature
session = auth.authenticate(address, challenge, signature)

# Access token
token = session.token

# Validate token
payload = auth.validate_token(token)

# Get user from token
user = auth.get_user_by_token(token)

# Logout (invalidate token)
auth.invalidate_token(token)
```

## Demo Application

A demonstration web application is included in the `web_demo` directory:

```bash
# Start the authentication API server
./start_auth_server.sh

# Start the demo web application
./start_web_demo.sh
```

Then visit `http://localhost:5000` in your browser.

## Testing

Run the tests with:

```bash
python3 -m unittest tests/test_auth.py
```

To skip tests that require a real Evrmore node:

```bash
SKIP_EVRMORE_TESTS=1 python3 -m unittest tests/test_auth.py
```

## Examples

See the `examples` directory for more usage examples.

## Recent Improvements

- **Automatic User Creation**: Users are now automatically created on first authentication
- **Flexible Signature Verification**: The system now tries multiple signature formats to accommodate different wallet implementations
- **Better Error Handling**: More informative error messages
- **Improved Security**: Proper token validation and expiration
- **Enhanced Logging**: Detailed logs for troubleshooting
- **Simplified API**: More concise and better documented code

## License

This software is provided by Manticore Technologies under the MIT license.

## Contact

- Website: [manticore.technology](https://manticore.technology)
- GitHub: [github.com/manticoretechnologies](https://github.com/manticoretechnologies)
- Email: dev@manticore.technology 