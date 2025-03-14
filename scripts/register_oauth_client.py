#!/usr/bin/env python3
"""
Evrmore Authentication OAuth Client Registration Script
----------------------------------------------------
Manticore Technologies - https://manticore.technology

This script provides a simple way to register new OAuth clients in the central database.
"""

import os
import sys
import argparse
import logging
import uuid
import secrets
import sqlite3
import datetime
from pathlib import Path
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("oauth-client-registration")

# Load environment variables
load_dotenv()

# Get the database path from environment
DB_PATH = os.getenv("SQLITE_DB_PATH", "./evrmore_authentication/data/evrmore_auth.db")

def ensure_db_dir_exists():
    """Ensure the database directory exists."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        logger.info(f"Created database directory: {db_dir}")

def connect_to_db():
    """Connect to the SQLite database."""
    ensure_db_dir_exists()
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    # Create tables if they don't exist
    cursor = conn.cursor()
    
    # Create OAuth 2.0 Client table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS oauth_clients (
        id TEXT PRIMARY KEY,
        client_id TEXT UNIQUE NOT NULL,
        client_secret TEXT NOT NULL,
        client_name TEXT NOT NULL,
        client_uri TEXT,
        redirect_uris TEXT NOT NULL,
        allowed_response_types TEXT NOT NULL,
        allowed_scopes TEXT NOT NULL,
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1
    )
    ''')
    
    conn.commit()
    logger.info(f"Connected to database at {DB_PATH}")
    return conn

def register_client(client_name, redirect_uris, client_uri=None, 
                   scopes="profile", response_types="code"):
    """Register a new OAuth client."""
    conn = connect_to_db()
    cursor = conn.cursor()
    
    # Generate IDs and secret
    client_id = str(uuid.uuid4())
    id = str(uuid.uuid4())
    client_secret = secrets.token_urlsafe(32)
    now = datetime.datetime.utcnow().isoformat()
    
    # Process redirect URIs
    if isinstance(redirect_uris, list):
        redirect_uris = ",".join(redirect_uris)
    
    # Insert the client
    try:
        cursor.execute(
            """INSERT INTO oauth_clients 
            (id, client_id, client_secret, client_name, client_uri, redirect_uris, 
            allowed_response_types, allowed_scopes, created_at, updated_at, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (id, client_id, client_secret, client_name, client_uri, redirect_uris,
             response_types, scopes, now, now, 1)
        )
        conn.commit()
        
        logger.info(f"Successfully registered new OAuth client:")
        logger.info(f"  - Name: {client_name}")
        logger.info(f"  - Client ID: {client_id}")
        logger.info(f"  - Client Secret: {client_secret}")
        logger.info(f"  - Redirect URIs: {redirect_uris}")
        
        result = {
            "id": id,
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "allowed_scopes": scopes,
            "allowed_response_types": response_types,
            "client_uri": client_uri
        }
        
        return result
    except Exception as e:
        logger.error(f"Error registering client: {str(e)}")
        conn.rollback()
        return None
    finally:
        conn.close()

def list_clients():
    """List all registered OAuth clients."""
    conn = connect_to_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM oauth_clients WHERE is_active = 1")
        clients = cursor.fetchall()
        
        if not clients:
            logger.info("No active OAuth clients found")
            return []
        
        logger.info(f"Found {len(clients)} active OAuth client(s):")
        results = []
        
        for client in clients:
            client_dict = dict(client)
            logger.info(f"  - Client Name: {client['client_name']}")
            logger.info(f"    * Client ID: {client['client_id']}")
            logger.info(f"    * Redirect URIs: {client['redirect_uris']}")
            logger.info("")
            results.append(client_dict)
            
        return results
    except Exception as e:
        logger.error(f"Error listing clients: {str(e)}")
        return []
    finally:
        conn.close()

def delete_client(client_id):
    """Delete (deactivate) an OAuth client."""
    conn = connect_to_db()
    cursor = conn.cursor()
    
    try:
        # Check if client exists
        cursor.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,))
        client = cursor.fetchone()
        
        if not client:
            logger.error(f"Client with ID {client_id} not found")
            return False
        
        # Deactivate the client
        now = datetime.datetime.utcnow().isoformat()
        cursor.execute(
            "UPDATE oauth_clients SET is_active = 0, updated_at = ? WHERE client_id = ?",
            (now, client_id)
        )
        conn.commit()
        
        logger.info(f"Successfully deactivated client: {client['client_name']} (ID: {client_id})")
        return True
    except Exception as e:
        logger.error(f"Error deleting client: {str(e)}")
        conn.rollback()
        return False
    finally:
        conn.close()

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Evrmore Authentication OAuth Client Registration Tool")
    subparsers = parser.add_subparsers(title="commands", dest="command")
    
    # Register command
    register_parser = subparsers.add_parser("register", help="Register a new OAuth client")
    register_parser.add_argument("--name", required=True, help="Client application name")
    register_parser.add_argument("--redirects", required=True, help="Comma-separated list of redirect URIs")
    register_parser.add_argument("--uri", help="Client application URI")
    register_parser.add_argument("--scopes", default="profile", help="Comma-separated list of allowed scopes")
    register_parser.add_argument("--response-types", default="code", help="Comma-separated list of allowed response types")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List all registered OAuth clients")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete (deactivate) an OAuth client")
    delete_parser.add_argument("--client-id", required=True, help="Client ID to delete")
    
    args = parser.parse_args()
    
    # Print database path
    logger.info(f"Using database at: {DB_PATH}")
    
    if args.command == "register":
        client = register_client(
            client_name=args.name,
            redirect_uris=args.redirects,
            client_uri=args.uri,
            scopes=args.scopes,
            response_types=args.response_types
        )
        
        if client:
            print("\nAdd these to your .env file or environment:")
            print(f"OAUTH_CLIENT_ID={client['client_id']}")
            print(f"OAUTH_CLIENT_SECRET={client['client_secret']}")
            print(f"OAUTH_REDIRECT_URI={client['redirect_uris'].split(',')[0]}")
            
    elif args.command == "list":
        list_clients()
        
    elif args.command == "delete":
        delete_client(args.client_id)
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 