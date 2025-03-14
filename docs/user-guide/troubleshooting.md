# Troubleshooting Guide

This guide provides tools and techniques for troubleshooting the Evrmore Authentication system, with a focus on the OAuth 2.0 implementation and common issues users might encounter.

## Debugging Tools

The Evrmore Authentication system includes several debugging tools that can help diagnose issues.

### Database Monitoring Tools

#### `check_db.py`

This script provides a simple way to check the contents of the SQLite database:

```bash
python3 check_db.py
```

It displays a summary of database contents including:
- Users
- Sessions
- Challenges
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
- Client Secret (partially masked)
- Name
- Redirect URIs
- Scopes
- Active status

### Log Monitoring

#### `monitor_logs.py`

This script provides real-time monitoring of the authentication server logs:

```bash
python3 monitor_logs.py
```

It tails the `auth_server.log` file and displays new log entries as they are added. This is useful for seeing detailed information about the authentication process, including debug messages and errors.

## Common Issues and Solutions

### OAuth 2.0 Issues

#### "Invalid client_id" Error

If you encounter an "Invalid client_id" error:

1. Verify that the client ID is registered in the database:
   ```bash
   python3 scripts/register_oauth_client.py list
   ```

2. Ensure the database path is consistent between your server and client:
   ```
   SQLITE_DB_PATH=./evrmore_authentication/data/evrmore_auth.db
   ```

3. Re-register the client if necessary:
   ```bash
   python3 scripts/register_oauth_client.py register \
       --name "Your App" --redirects "http://your-app.com/callback"
   ```

#### "Missing or expired OAuth session" Error

This error occurs when the OAuth session cookie is missing or invalid:

1. Ensure cookies are properly stored and have appropriate security settings
2. Check that the session duration is sufficient
3. Verify the state parameter is properly managed

#### Authorization Code Exchange Fails (422 Error)

If token exchange fails with a 422 error:

1. Ensure the content type is correctly set for the token request:
   ```python
   headers={"Content-Type": "application/x-www-form-urlencoded"}
   ```

2. Verify that you're sending form data rather than JSON:
   ```python
   # Correct:
   requests.post(url, data={"grant_type": "authorization_code", ...})
   
   # Incorrect:
   requests.post(url, json={"grant_type": "authorization_code", ...})
   ```

3. Check that all required parameters are included:
   - `grant_type`
   - `code`
   - `redirect_uri`
   - `client_id`
   - `client_secret`

### Authentication Issues

#### "Failed to verify signature" Error

If signature verification fails:

1. Ensure the user is signing the exact challenge text provided
2. Check that the signature and Evrmore address match
3. Make sure you're using the correct verification order in any custom code:
   ```python
   # Correct order:
   verify_message(address, message, signature)
   ```

4. Ensure the signature was created using the correct wallet

#### Challenge Expiration Issues

Challenges are designed to expire after a set time (default: 15 minutes):

1. Check if the challenge has expired:
   ```python
   challenge_details = auth.get_challenge_details(challenge_text)
   print(f"Expires at: {challenge_details.expires_at}")
   ```

2. Generate a new challenge if needed:
   ```python
   new_challenge = auth.generate_challenge(evrmore_address)
   ```

3. Adjust the expiration time if challenges expire too quickly:
   ```python
   # Set longer expiration (30 minutes)
   challenge = auth.generate_challenge(evrmore_address, expire_minutes=30)
   ```

### Database Issues

#### Missing Tables

If you see errors about missing tables, initialize the database:
```bash
python3 -m scripts.db_manage init
```

#### Database Path Mismatch

Ensure your `.env` file has the correct path:
```
SQLITE_DB_PATH=./evrmore_authentication/data/evrmore_auth.db
```

#### SQLite Permissions

If you get permission errors, check file permissions on the database file and directory:
```bash
# Check permissions
ls -la ./evrmore_authentication/data/

# Fix permissions if needed
chmod 644 ./evrmore_authentication/data/evrmore_auth.db
chmod 755 ./evrmore_authentication/data/
```

### Server Issues

#### Server Won't Start

Check that the port is not already in use:
```bash
# Check if port 8001 is in use
lsof -i :8001

# Kill the process using the port
pkill -f "python3 -m scripts.run_api_server"
```

#### CORS Errors

If you're getting CORS errors in the browser, check the CORS configuration in the API server:

1. Ensure the client domain is allowed
2. Use the `--allow-origins` flag when starting the server:
   ```bash
   python3 -m scripts.run_api_server --port 8001 --allow-origins "http://localhost:8000,https://your-app.com"
   ```

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

## Debug Mode

Enable debug mode in your `.env` file to get more detailed logs:
```
DEBUG_MODE=True
LOG_LEVEL=DEBUG
```

This will provide verbose logging for all operations, making it easier to identify the source of issues.

## Getting Help

If you encounter persistent issues:

1. Check the [GitHub Issues](https://github.com/manticoretechnologies/evrmore-authentication/issues) for similar problems and solutions.

2. Contact support:
   - Email: dev@manticore.technology
   - GitHub: https://github.com/manticoretechnologies 