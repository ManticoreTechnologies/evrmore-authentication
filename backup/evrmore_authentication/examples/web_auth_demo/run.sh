#!/bin/bash
# Run script for Evrmore Authentication Web Demo (API-based)

# Get the absolute path to the project root
PROJECT_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXAMPLE_DIR=$(cd "$(dirname "$0")" && pwd)

echo "Project root: $PROJECT_ROOT"
echo "Example directory: $EXAMPLE_DIR"

# Install required packages
echo "Installing required packages..."
cd "$EXAMPLE_DIR" && pip3 install -r requirements.txt

# Make sure the logo exists
if [ ! -f "$EXAMPLE_DIR/static/evrmore-logo.png" ]; then
    echo "Creating placeholder for Evrmore logo..."
    mkdir -p "$EXAMPLE_DIR/static"
    # Create a simple placeholder image or download it
    curl -s -o "$EXAMPLE_DIR/static/evrmore-logo.png" https://raw.githubusercontent.com/EvrmoreOrg/evrmore-graphics/master/evrmore-logos/evrmore-logo-white-text.png || echo "Failed to download logo, using a placeholder."
fi

# Create a .env file if it doesn't exist
if [ ! -f "$EXAMPLE_DIR/.env" ]; then
    echo "Creating .env file with default settings..."
    cat > "$EXAMPLE_DIR/.env" << EOF
# Flask configuration
SECRET_KEY=evrmore-auth-demo-secret-key
FLASK_DEBUG=True
PORT=5000

# Evrmore Authentication API configuration
API_BASE_URL=http://localhost:8000
CHALLENGE_EXPIRE_MINUTES=10
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
EOF
    echo "Created .env file with default settings"
else
    echo "Using existing .env file"
fi

# Check if API server is running
API_BASE_URL=$(grep API_BASE_URL "$EXAMPLE_DIR/.env" | cut -d= -f2)
echo "Checking if API server is running at $API_BASE_URL..."
if ! curl -s "$API_BASE_URL" &>/dev/null; then
    echo "WARNING: API server does not appear to be running at $API_BASE_URL"
    echo "Make sure to start the API server first with: ./run_api_server.py"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run the application
echo "Starting Evrmore Authentication Web Demo..."
echo "The application will be available at http://localhost:5000"
cd "$EXAMPLE_DIR" && python3 app.py 