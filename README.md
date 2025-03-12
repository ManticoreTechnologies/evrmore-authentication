<!-- omit in toc -->
<div align="center">
  <img src="docs/assets/images/logo.svg" alt="Evrmore Authentication" width="250">
  <h1>Evrmore Authentication</h1>
  
  <p>A secure wallet-based authentication system for Evrmore blockchain applications</p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
  [![PyPI version](https://badge.fury.io/py/evrmore-authentication.svg)](https://badge.fury.io/py/evrmore-authentication)
</div>

<!-- omit in toc -->
## 📋 Table of Contents

- [✨ Overview](#-overview)
- [🚀 Quick Start](#-quick-start)
  - [Installation](#installation)
  - [Running the API Server](#running-the-api-server)
  - [Running the Web Demo](#running-the-web-demo)
- [🧰 System Requirements](#-system-requirements)
- [🔐 Authentication Flow](#-authentication-flow)
- [📘 Usage in Your Application](#-usage-in-your-application)
  - [Basic Authentication Flow](#basic-authentication-flow)
  - [FastAPI Integration](#fastapi-integration)
- [⚙️ Configuration](#️-configuration)
- [📚 Documentation](#-documentation)
- [💻 Development](#-development)
  - [Project Structure](#project-structure)
  - [Setup Development Environment](#setup-development-environment)
  - [Running Tests](#running-tests)
  - [Building Documentation Locally](#building-documentation-locally)
- [📄 License](#-license)
- [📞 Contact](#-contact)

## ✨ Overview

Evrmore Authentication is a Python package that provides wallet-based authentication using Evrmore signature verification. This allows users to authenticate to web applications using their Evrmore wallet without sharing their private keys, creating a secure and user-friendly authentication experience.

**Key Features:**

- **🔑 Wallet-based authentication** - Users sign a challenge message with their Evrmore wallet
- **🔒 JWT token management** - Secure session handling with JSON Web Tokens
- **📁 SQLite backend** - Simple, file-based database for session and challenge storage
- **👤 Automatic user management** - Users are created on first authentication
- **🌐 Complete API server** - Ready-to-use FastAPI server for authentication endpoints
- **🖥️ Demo web interface** - Example Flask application showing the complete authentication flow

## 🚀 Quick Start

### Installation

```bash
pip3 install evrmore-authentication
```

### Running the API Server

```bash
python3 -m scripts.run_api_server --host 0.0.0.0 --port 8000
```

### Running the Web Demo

```bash
python3 -m scripts.run_web_demo --port 5000 --api-url http://localhost:8000
```

## 🧰 System Requirements

- Python 3.7 or higher
- SQLite database for session and challenge storage
- Evrmore node (for signature verification)

## 🔐 Authentication Flow

<div align="center">
  <table>
    <tr>
      <td align="center"><b>1. Challenge Generation</b></td>
      <td>The server generates a unique challenge for the user's Evrmore address</td>
    </tr>
    <tr>
      <td align="center"><b>2. Signature Creation</b></td>
      <td>The user signs the challenge with their Evrmore wallet</td>
    </tr>
    <tr>
      <td align="center"><b>3. Verification</b></td>
      <td>The server verifies the signature against the challenge</td>
    </tr>
    <tr>
      <td align="center"><b>4. Token Issuance</b></td>
      <td>Upon successful verification, a JWT token is issued</td>
    </tr>
    <tr>
      <td align="center"><b>5. Authentication</b></td>
      <td>The token is used for subsequent API requests</td>
    </tr>
  </table>
</div>

## 📘 Usage in Your Application

### Basic Authentication Flow

```python
from evrmore_authentication import EvrmoreAuth
from evrmore_rpc import EvrmoreClient

# Initialize the authentication system with an Evrmore client
client = EvrmoreClient()
auth = EvrmoreAuth(client)

# Generate a challenge for a user's Evrmore address
challenge = auth.generate_challenge("EXaMPLeEvRMoReAddResS")

# Verify the signature provided by the user
session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature="signed_challenge_from_wallet"
)

# Use the token for authentication
token = session.token

# Validate a token
token_data = auth.validate_token(token)

# Get user from token
user = auth.get_user_by_token(token)

# Invalidate a token (logout)
auth.invalidate_token(token)
```

### FastAPI Integration

The package includes a ready-to-use FastAPI server with the following endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenge` | POST | Generate a challenge for a user |
| `/authenticate` | POST | Authenticate with a signed challenge |
| `/validate` | GET | Validate a JWT token |
| `/me` | GET | Get authenticated user information |
| `/logout` | POST | Invalidate a JWT token (logout) |

## ⚙️ Configuration

Configuration is done through environment variables or a `.env` file:

```ini
# SQLite configuration
SQLITE_DB_PATH=./data/evrmore_auth.db

# JWT configuration
JWT_SECRET=your-secure-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Challenge configuration
CHALLENGE_EXPIRE_MINUTES=10
```

## 📚 Documentation

For more information, please see:

- [📖 User Guide](docs/user-guide/index.md)
- [🔍 API Reference](docs/api-reference/index.md)
- [📔 Online Documentation](https://manticoretechnologies.github.io/evrmore-authentication/)

## 💻 Development

### Project Structure

```
evrmore-authentication/
├── evrmore_authentication/    # Main package
│   ├── __init__.py            # Package initialization
│   ├── auth.py                # Core authentication logic
│   ├── api.py                 # FastAPI endpoints
│   ├── models.py              # Database models
│   ├── exceptions.py          # Custom exceptions
│   └── dependencies.py        # FastAPI dependencies
├── scripts/                   # Utility scripts
│   ├── run_api_server.py      # API server runner
│   └── run_web_demo.py        # Web demo runner
├── examples/                  # Example applications
│   ├── demo.py                # Simple CLI demo
│   └── web_auth_demo/         # Web application example
├── tests/                     # Test suite
├── docs/                      # Documentation
└── setup.py                   # Package setup
```

### Setup Development Environment

```bash
git clone https://github.com/manticoretechnologies/evrmore-authentication.git
cd evrmore-authentication
pip3 install -e .
```

### Running Tests

```bash
pytest
```

### Building Documentation Locally

```bash
# Install MkDocs and the Material theme
pip3 install mkdocs-material

# Serve the documentation locally at http://127.0.0.1:8000
mkdocs serve

# Build the documentation
mkdocs build
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact

<div align="center">
  <table>
    <tr>
      <td align="center"><b>🏢 Organization</b></td>
      <td><a href="https://manticore.technology">Manticore Technologies</a></td>
    </tr>
    <tr>
      <td align="center"><b>🌐 Website</b></td>
      <td><a href="https://manticore.technology">manticore.technology</a></td>
    </tr>
    <tr>
      <td align="center"><b>📂 GitHub</b></td>
      <td><a href="https://github.com/manticoretechnologies">github.com/manticoretechnologies</a></td>
    </tr>
    <tr>
      <td align="center"><b>✉️ Email</b></td>
      <td><a href="mailto:dev@manticore.technology">dev@manticore.technology</a></td>
    </tr>
  </table>
</div>

---

<div align="center">
  <p>Built with ❤️ by <a href="https://manticore.technology">Manticore Technologies</a></p>
</div> 