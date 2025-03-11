#!/usr/bin/env python3
"""
Evrmore Authentication API Server

This script runs the Evrmore Authentication REST API server.
"""

import os
import sys
import argparse
import logging
from dotenv import load_dotenv

# Ensure the evrmore_authentication package is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Run the API server with command-line arguments."""
    # Load environment variables from .env file
    load_dotenv()
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run the Evrmore Authentication API server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    parser.add_argument('--workers', type=int, default=1, help='Number of worker processes')
    parser.add_argument('--log-level', type=str, default='info', 
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Log level')
    parser.add_argument('--no-init-db', action='store_true', 
                        help='Skip database initialization on startup')
    
    args = parser.parse_args()
    
    # Set log level
    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)
    
    # Initialize the database if not disabled
    if not args.no_init_db:
        try:
            logger.info("Initializing database...")
            from evrmore_authentication.db import init_db
            init_db()
            logger.info("Database initialization complete")
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            if args.log_level == 'debug':
                import traceback
                logger.debug(traceback.format_exc())
    
    logger.info(f"Starting Evrmore Authentication API server on {args.host}:{args.port}")
    
    # Import and run the API
    from evrmore_authentication.api import run_api
    
    run_api(
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level=args.log_level
    )

if __name__ == '__main__':
    main() 