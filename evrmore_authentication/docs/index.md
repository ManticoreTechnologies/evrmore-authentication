# Evrmore Authentication

![Evrmore Authentication](https://raw.githubusercontent.com/manticoretechnologies/evrmore-authentication/main/docs/logo.png)

*Secure blockchain-based authentication using Evrmore wallet signatures*

---

## What is Evrmore Authentication?

Evrmore Authentication is a Python package that provides a secure, blockchain-based authentication system for your applications. It leverages Evrmore wallet signatures to verify user identity without storing passwords.

## Features

- **Blockchain-based Authentication**: Uses Evrmore wallet signatures for secure user authentication
- **Challenge-Response Protocol**: Generates unique challenges for each authentication attempt
- **PostgreSQL Integration**: Stores user data and session information in a PostgreSQL database
- **Atomic Operations**: Ensures transaction integrity with database-level atomicity
- **JWT Support**: Issues and validates JSON Web Tokens for authenticated sessions
- **Modern Auth Workflows**: Supports standard OAuth2 flows
- **Comprehensive Security**: Protection against common attack vectors

## Why Use Blockchain Authentication?

Traditional password-based authentication has many weaknesses:

- Password reuse across sites
- Vulnerability to phishing attacks
- Security breaches exposing password hashes
- Password recovery complexity

Blockchain-based authentication solves these issues by:

- Eliminating passwords entirely
- Using proven cryptographic signing
- Preventing replay attacks
- Providing decentralized identity verification

## Quick Links

- [Getting Started](./guide.md#installation)
- [Configuration](./guide.md#configuration)
- [API Documentation](./api.md)
- [FastAPI Integration](./guide.md#fastapi-integration)
- [Security Considerations](./guide.md#security-considerations)
- [GitHub Repository](https://github.com/manticoretechnologies/evrmore-authentication)

## About Manticore Technologies

[Manticore Technologies](https://manticore.technology) specializes in blockchain integration and development solutions. Visit our website to learn more about our services and projects. 