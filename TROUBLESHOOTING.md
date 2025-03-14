# Evrmore Authentication Troubleshooting Guide

This guide provides tools and techniques for troubleshooting the Evrmore Authentication system, with a focus on the OAuth 2.0 implementation.

## Debugging Tools

The repository includes several useful debugging tools that can help diagnose issues with the authentication system.

### Database Monitoring

#### `check_db.py`

This script provides a simple way to check the contents of the SQLite database:

```bash
python3 check_db.py
```

It displays a summary of:
- Authorization Codes
- OAuth Clients

#### `check_auth_codes.py`

This script provides real-time monitoring of OAuth authorization codes in the database:

```bash
python3 check_auth_codes.py
```

It shows detailed information about each authorization code, including:
- Code value
- Client ID
- User ID
- Redirect URI
- Scope
- Creation and expiration timestamps
- Used status

This tool is particularly useful for debugging the OAuth authorization code flow, as you can see the codes being created and used in real-time.

#### `check_oauth_clients.py`

This script checks for registered OAuth clients in the database:

```bash
python3 check_oauth_clients.py
```

It displays a list of all registered OAuth clients, including:
- Client ID
- Client Secret
- Name
- Redirect URIs
- Active status

### Log Monitoring

#### `monitor_logs.py`

This script provides real-time monitoring of the authentication server logs:

```bash
python3 monitor_logs.py
```

It tails the `auth_server.log` file and displays new log entries as they are added. This is useful for seeing detailed information about the authentication process, including debug messages and errors.

## Common Issues and Solutions

### Database Issues

1. **Missing Tables**: If you see errors about missing tables, initialize the database:
   ```bash
   python3 -m scripts.db_manage init
   ```

2. **Database Path Mismatch**: Ensure your `.env` file has the correct path:
   ```
   SQLITE_DB_PATH=./evrmore_authentication/data/evrmore_auth.db
   ```

3. **SQLite Permissions**: If you get permission errors, check file permissions on the database file and directory.

### OAuth Issues

See the [OAuth 2.0 Implementation Guide](OAUTH_GUIDE.md) for detailed troubleshooting of OAuth-specific issues.

### Signature Verification Issues

1. **Incorrect Signature Format**: Ensure signatures are in the correct format expected by the system.

2. **Challenge Expiry**: Challenges expire after a set time (default: 15 minutes). If a challenge has expired, a new one must be generated.

3. **Parameter Order**: If you've customized the signature verification code, ensure parameters are passed in the correct order:
   ```python
   # Correct:
   verify_message(address, message, signature)
   
   # Incorrect:
   verify_message(message, address, signature)
   ```

### Server Issues

1. **Server Won't Start**: Check that the port is not already in use:
   ```bash
   # Check if port 8001 is in use
   lsof -i :8001
   
   # Kill the process using the port
   pkill -f "python3 -m scripts.run_api_server"
   ```

2. **CORS Errors**: If you're getting CORS errors in the browser, check the CORS configuration in the API server.

## Running Tests

The test suite can help diagnose issues:

```bash
# Run all tests
python3 -m pytest

# Run specific tests
python3 -m pytest evrmore_authentication/tests/unit/test_auth.py

# Run tests with verbose output
python3 -m pytest -v
```

## Getting Help

If you encounter persistent issues:

1. Check the [GitHub Issues](https://github.com/manticoretechnologies/evrmore-authentication/issues) for similar problems and solutions.

2. Enable debug mode in your `.env` file to get more detailed logs:
   ```
   DEBUG_MODE=True
   LOG_LEVEL=DEBUG
   ```

3. Contact support:
   - Email: dev@manticore.technology
   - GitHub: https://github.com/manticoretechnologies 