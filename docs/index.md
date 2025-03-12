# Evrmore Authentication

<div align="center">
  <img src="assets/images/logo.svg" alt="Evrmore Authentication" width="200">
  <h1>Evrmore Authentication</h1>
  <p>Secure blockchain-based authentication using Evrmore wallet signatures</p>
</div>

## Overview

Evrmore Authentication is a Python package that provides a secure, blockchain-based authentication system for your applications. It leverages Evrmore wallet signatures to verify user identity without storing passwords.

## Key Features

- **Blockchain-based Authentication**: Uses Evrmore wallet signatures for secure user authentication
- **Challenge-Response Protocol**: Generates unique challenges for each authentication attempt
- **Multiple Backend Options**: Supports PostgreSQL and Redis as backend storage
- **JWT Support**: Issues and validates JSON Web Tokens for authenticated sessions
- **FastAPI Integration**: Ready-to-use FastAPI endpoints for authentication
- **Comprehensive Security**: Protection against common attack vectors

## Quick Start

```bash
# Install the package
pip3 install evrmore-authentication

# Run the API server
python3 -m scripts.run_api_server --host 0.0.0.0 --port 8000

# Run the web demo
python3 -m scripts.run_web_demo --port 5000 --api-url http://localhost:8000
```

## Documentation Sections

- [User Guide](user-guide/index.md) - Comprehensive guide for using the package
- [API Reference](api-reference/index.md) - Detailed technical reference
- [Examples](examples/index.md) - Code examples and tutorials
- [Development](development/index.md) - Contributing to the project

## Authentication Flow

1. **Challenge Generation**: The server generates a unique challenge for a user's Evrmore address
2. **Signature Creation**: The user signs the challenge with their Evrmore wallet
3. **Verification**: The server verifies the signature against the challenge
4. **Token Issuance**: Upon successful verification, a JWT token is issued
5. **Authentication**: The token is used for subsequent API requests

## About Manticore Technologies

[Manticore Technologies](https://manticore.technology) specializes in blockchain integration and development solutions. Visit our website to learn more about our services and projects. 