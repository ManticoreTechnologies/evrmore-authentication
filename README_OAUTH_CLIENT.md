# OAuth Client Registration Guide

This guide explains how to register OAuth clients for use with the Evrmore Authentication system.

## Using the Client Registration Script

The `register_oauth_client.py` script provides a simple way to manage OAuth clients with our central database.

### Prerequisites

Before using this script, ensure:

1. You have the Evrmore Authentication server properly set up
2. Your `.env` file has the correct `SQLITE_DB_PATH` configuration
3. You have Python 3.7+ and the required dependencies installed

### Commands

#### Register a New Client

```bash
python3 scripts/register_oauth_client.py register \
    --name "Your App Name" \
    --redirects "http://localhost:3000/callback,http://localhost:3000/oauth/callback" \
    --uri "http://localhost:3000" \
    --scopes "profile,email" \
    --response-types "code"
```

Options:
- `--name`: Name of your application (required)
- `--redirects`: Comma-separated list of allowed redirect URIs (required)
- `--uri`: Your application's home URI (optional)
- `--scopes`: Comma-separated list of allowed scopes (default: "profile")
- `--response-types`: Comma-separated list of allowed response types (default: "code")

After successful registration, the script will output your client credentials, which you should add to your application's environment variables or `.env` file.

#### List Registered Clients

```bash
python3 scripts/register_oauth_client.py list
```

This command lists all active OAuth clients in the database, showing their names, client IDs, and redirect URIs.

#### Delete (Deactivate) a Client

```bash
python3 scripts/register_oauth_client.py delete --client-id YOUR_CLIENT_ID
```

This command deactivates the specified client, preventing it from being used for authentication.

## Using the Client Credentials

After registering a client, you can use the credentials in your application. Create a `.env.oauth` file in your project root with:

```
# OAuth Client Credentials
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=your_redirect_uri

# Authorization Server Settings
AUTH_SERVER_URL=http://localhost:8001
```

In your application, load these environment variables:

```python
from dotenv import load_dotenv
load_dotenv('.env.oauth')

client_id = os.environ.get("OAUTH_CLIENT_ID")
client_secret = os.environ.get("OAUTH_CLIENT_SECRET")
redirect_uri = os.environ.get("OAUTH_REDIRECT_URI")
auth_server = os.environ.get("AUTH_SERVER_URL")
```

## One Database Rule

To ensure consistency, all components should use the same database:

1. All scripts and servers should use the same `SQLITE_DB_PATH` value from the `.env` file
2. The database should be initialized using `python3 -m scripts.db_manage init`
3. OAuth clients registered with one database instance will only work with that same instance

By following these guidelines, you'll ensure that your OAuth clients are correctly registered and available to your applications. 