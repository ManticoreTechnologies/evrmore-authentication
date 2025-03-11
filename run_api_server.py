#!/usr/bin/env python3
"""
Direct script to run the Evrmore Authentication API server with Redis support.
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-auth-api")

# Load environment variables
load_dotenv()

# Force Redis configuration - ONLY USING REDIS
os.environ["DB_TYPE"] = "redis"
os.environ["REDIS_HOST"] = os.getenv("REDIS_HOST", "localhost")
os.environ["REDIS_PORT"] = os.getenv("REDIS_PORT", "6379")
os.environ["REDIS_DB"] = os.getenv("REDIS_DB", "0")
os.environ["REDIS_PASSWORD"] = os.getenv("REDIS_PASSWORD", "")

# Make sure JWT_SECRET is set
if not os.getenv("JWT_SECRET"):
    import secrets
    jwt_secret = secrets.token_hex(32)
    os.environ["JWT_SECRET"] = jwt_secret
    print(f"JWT_SECRET not set in environment. Using a generated value for this session: {jwt_secret[:5]}...")

# Make sure PostgreSQL and SQLite settings are explicitly empty
os.environ["DB_HOST"] = ""
os.environ["DB_PORT"] = ""
os.environ["DB_NAME"] = ""
os.environ["DB_USER"] = ""
os.environ["DB_PASSWORD"] = ""
os.environ["SQLITE_DB_PATH"] = ""

# Test Redis connection before starting server
try:
    import redis
    r = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        password=os.getenv("REDIS_PASSWORD", "") or None,
        decode_responses=True
    )
    if r.ping():
        logger.info(f"✅ Successfully connected to Redis at {os.getenv('REDIS_HOST')}:{os.getenv('REDIS_PORT')}")
    else:
        logger.error("⛔ Redis ping failed!")
        sys.exit(1)
except Exception as e:
    logger.error(f"⛔ Redis connection error: {str(e)}")
    logger.error("Cannot start API server without Redis. Please ensure Redis is running.")
    sys.exit(1)

# Import API runner after confirming Redis is available
from evrmore_authentication.api import run_api

if __name__ == "__main__":
    import argparse
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run Evrmore Authentication API Server with Redis')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    
    args = parser.parse_args()
    
    # Log Redis connection info
    logger.info(f"Using Redis at {os.getenv('REDIS_HOST')}:{os.getenv('REDIS_PORT')} database {os.getenv('REDIS_DB')}")
    logger.info("⚠️ USING REDIS ONLY - All other database backends have been disabled")
    
    # Run the API
    logger.info(f"Starting API server on {args.host}:{args.port}")
    run_api(host=args.host, port=args.port, reload=args.reload) 