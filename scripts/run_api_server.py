#!/usr/bin/env python3
"""
Evrmore Authentication API Server Entry Point
--------------------------------------------
Manticore Technologies - https://manticore.technology

This script runs the Evrmore Authentication API server with SQLite support.
"""

import os
import sys
import logging
import argparse
import secrets
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-auth-api")

# Load environment variables
load_dotenv()

# Force SQLite configuration
os.environ["DB_TYPE"] = "sqlite"
os.environ["SQLITE_DB_PATH"] = os.getenv("SQLITE_DB_PATH", "./data/evrmore_auth.db")

# Make sure JWT_SECRET is set
if not os.getenv("JWT_SECRET"):
    jwt_secret = secrets.token_hex(32)
    os.environ["JWT_SECRET"] = jwt_secret
    logger.info(f"JWT_SECRET not set in environment. Using a generated value for this session: {jwt_secret[:5]}...")

# Ensure SQLite database directory exists
sqlite_db_path = os.getenv("SQLITE_DB_PATH", "./data/evrmore_auth.db")
db_dir = os.path.dirname(sqlite_db_path)
if db_dir and not os.path.exists(db_dir):
    try:
        os.makedirs(db_dir, exist_ok=True)
        logger.info(f"Created database directory: {db_dir}")
    except Exception as e:
        logger.error(f"⛔ Error creating database directory: {str(e)}")
        sys.exit(1)

def main():
    """Run the API server with the specified configuration."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run Evrmore Authentication API Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    
    args = parser.parse_args()
    
    # Log SQLite connection info
    logger.info(f"Using SQLite database at {os.getenv('SQLITE_DB_PATH')}")
    
    # Run the API
    logger.info(f"Starting API server on {args.host}:{args.port}")
    
    # Import here to avoid circular imports and allow environment setup first
    from evrmore_authentication.api import run_api
    run_api(host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main() 