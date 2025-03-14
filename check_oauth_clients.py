#!/usr/bin/env python3
"""
Evrmore Authentication OAuth Client Check Tool
--------------------------------------------
Manticore Technologies - https://manticore.technology

This script checks OAuth clients in all available database files.
"""

import os
import sys
import sqlite3
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("oauth-client-checker")

def check_database(db_path):
    """Check for OAuth clients in a database file."""
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        return

    logger.info(f"Checking database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if the table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_clients'")
        if not cursor.fetchone():
            logger.info(f"  - No oauth_clients table found in this database")
            return
        
        # Get all OAuth clients
        cursor.execute("SELECT * FROM oauth_clients")
        clients = cursor.fetchall()
        
        if not clients:
            logger.info(f"  - No OAuth clients found in this database")
            return
        
        logger.info(f"  - Found {len(clients)} OAuth client(s):")
        for client in clients:
            logger.info(f"    * Client ID: {client['client_id']}")
            logger.info(f"      - Name: {client['client_name']}")
            logger.info(f"      - Secret: {client['client_secret']}")
            logger.info(f"      - Redirect URIs: {client['redirect_uris']}")
            logger.info(f"      - Active: {bool(client['is_active'])}")
            logger.info("")
            
    except Exception as e:
        logger.error(f"Error checking database {db_path}: {str(e)}")

def main():
    """Main entry point."""
    # List of possible database locations
    db_paths = [
        "./evrmore_auth.db",
        "./data/evrmore_auth.db",
        "./evrmore_authentication/data/evrmore_auth.db",
    ]
    
    for db_path in db_paths:
        check_database(db_path)

if __name__ == "__main__":
    main() 