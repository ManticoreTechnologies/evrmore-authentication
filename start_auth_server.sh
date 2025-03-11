#!/bin/bash
# Comprehensive startup script for Evrmore Authentication API Server
# Created by Manticore Technologies - https://manticore.technology

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print with color
print_green() { echo -e "${GREEN}$1${NC}"; }
print_yellow() { echo -e "${YELLOW}$1${NC}"; }
print_red() { echo -e "${RED}$1${NC}"; }
print_blue() { echo -e "${BLUE}$1${NC}"; }

# Set working directory to script location
cd "$(dirname "$0")" || exit

# Header
clear
print_blue "==============================================================="
print_blue "     Evrmore Authentication API Server - Startup Script"
print_blue "==============================================================="
print_blue " Manticore Technologies - https://manticore.technology"
print_blue "---------------------------------------------------------------"
echo

# Check for Python 3
print_yellow "Checking for Python 3..."
if ! command -v python3 &> /dev/null; then
    print_red "Error: Python 3 is required but not found."
    echo "Please install Python 3 and try again."
    exit 1
fi
python3_version=$(python3 --version)
print_green "✓ Found $python3_version"
echo

# Check for pip3
print_yellow "Checking for pip3..."
if ! command -v pip3 &> /dev/null; then
    print_red "Error: pip3 is required but not found."
    echo "Please install pip3 and try again."
    exit 1
fi
pip3_version=$(pip3 --version)
print_green "✓ Found pip3"
echo

# Install or update required packages
print_yellow "Installing required packages..."
pip3 install -e . > /dev/null
if [ $? -ne 0 ]; then
    print_red "Error: Failed to install packages."
    exit 1
fi
print_green "✓ Required packages installed successfully"
echo

# Create .env file if it doesn't exist
print_yellow "Setting up environment variables..."
if [ ! -f .env ]; then
    echo "Creating .env file with default settings..."
    cat > .env << EOF
# Database configuration
DB_TYPE=sqlite
SQLITE_DB_PATH=./evrmore_auth.db

# JWT configuration
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Challenge configuration
CHALLENGE_EXPIRE_MINUTES=10

# API configuration
DEBUG=true
CORS_ORIGINS=*
EOF
    print_green "✓ Created .env file with default settings"
else
    print_green "✓ Using existing .env file"
fi
echo

# Initialize database
print_yellow "Initializing database..."
python3 - << EOF
import os
os.environ["DB_TYPE"] = "sqlite"
os.environ["SQLITE_DB_PATH"] = "./evrmore_auth.db"
from evrmore_authentication.db import init_db
init_db()
print("Database initialized successfully")
EOF
if [ $? -ne 0 ]; then
    print_red "Error: Failed to initialize database."
    exit 1
fi
print_green "✓ Database initialized successfully"
echo

# Check if Evrmore node is available
print_yellow "Checking Evrmore node availability..."
if command -v evrmore-cli &> /dev/null; then
    print_green "✓ Evrmore CLI is available"
    
    # Check if Evrmore node is running
    if evrmore-cli getblockchaininfo &> /dev/null; then
        print_green "✓ Evrmore node is running"
        NODE_INFO=$(evrmore-cli getblockchaininfo | grep -E 'blocks|chain')
        echo "   $NODE_INFO"
    else
        print_yellow "⚠ Evrmore node is not running or not accessible"
        echo "   Some functionality may be limited"
    fi
else
    print_yellow "⚠ Evrmore CLI not found"
    echo "   Signature verification may not work"
fi
echo

# Find an available port
print_yellow "Finding available port..."
PORT=8000
while nc -z localhost $PORT 2>/dev/null; do
    echo "   Port $PORT is in use, trying next..."
    PORT=$((PORT+1))
done
print_green "✓ Using port $PORT"
echo

# Start the API server
print_blue "==============================================================="
print_blue "     Starting Evrmore Authentication API Server"
print_blue "==============================================================="
print_yellow "Server will be available at: http://localhost:$PORT"
print_yellow "Press Ctrl+C to stop the server"
echo

# Source the .env file if it exists
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# Set environment variables for SQLite
export DB_TYPE=sqlite
export SQLITE_DB_PATH=./evrmore_auth.db

# Start the server
evrmore-auth-api --host 0.0.0.0 --port $PORT 