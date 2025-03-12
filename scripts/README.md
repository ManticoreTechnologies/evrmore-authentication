# Evrmore Authentication Scripts

This directory contains scripts for running various components of the Evrmore Authentication system.

## Available Scripts

### `run_api_server.py`

Runs the Evrmore Authentication API server.

```bash
python3 -m scripts.run_api_server --host 0.0.0.0 --port 8000
```

Options:
- `--host`: Host to bind to (default: 0.0.0.0)
- `--port`: Port to bind to (default: 8000)
- `--reload`: Enable auto-reload for development

### `run_web_demo.py`

Runs the web demo frontend that demonstrates the authentication flow.

```bash
python3 -m scripts.run_web_demo --port 5000 --api-url http://localhost:8000
```

Options:
- `--port`: Port to bind the web demo to (default: 5000)
- `--api-url`: URL of the Evrmore Authentication API (default: http://localhost:8000)

## Usage as Entry Points

These scripts are also registered as entry points and can be run directly after installing the package:

```bash
# Run API server
evrmore-auth-api --port 8000

# Run web demo
evrmore-auth-web --port 5000 --api-url http://localhost:8000
``` 