#!/usr/bin/env python3
"""
Script to check OAuth authorization codes in the database.
"""

import sqlite3
import sys
import time
import os
from datetime import datetime
from pathlib import Path

DB_PATH = "./evrmore_authentication/data/evrmore_auth.db"

def get_auth_codes():
    """Get all authorization codes from the database."""
    if not os.path.exists(DB_PATH):
        print(f"Database file not found: {DB_PATH}")
        return []
        
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM oauth_authorization_codes ORDER BY created_at DESC")
        codes = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return codes
    except Exception as e:
        print(f"Error querying database: {str(e)}")
        return []

def print_auth_codes(codes):
    """Print authorization codes in a readable format."""
    if not codes:
        print("No authorization codes found")
        return
        
    print(f"Found {len(codes)} authorization code(s):")
    for code in codes:
        # Convert timestamps to datetime objects
        expires_at = datetime.fromisoformat(code['expires_at']) if code['expires_at'] else None
        created_at = datetime.fromisoformat(code['created_at']) if code['created_at'] else None
        
        # Check if expired
        now = datetime.utcnow()
        is_expired = expires_at and now > expires_at
        
        # Format for display
        print(f"Code: {code['code']}")
        print(f"  ID: {code['id']}")
        print(f"  Client ID: {code['client_id']}")
        print(f"  User ID: {code['user_id']}")
        print(f"  Redirect URI: {code['redirect_uri']}")
        print(f"  Scope: {code['scope']}")
        print(f"  Created: {created_at}")
        print(f"  Expires: {expires_at} ({'EXPIRED' if is_expired else 'valid'})")
        print(f"  Used: {bool(code['used'])}")
        print()

def monitor():
    """Monitor authorization codes continuously."""
    print(f"Monitoring authorization codes in: {DB_PATH}")
    print("Press Ctrl+C to exit")
    print()
    
    try:
        while True:
            codes = get_auth_codes()
            os.system('clear')  # Clear terminal
            print(f"== Auth Codes at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ==")
            print_auth_codes(codes)
            time.sleep(2)  # Check every 2 seconds
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    monitor() 