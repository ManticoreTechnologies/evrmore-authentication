#!/usr/bin/env python3
"""
Force SQLite configuration and initialize the database.
"""

import os
import sys

# Force SQLite configuration
os.environ["DB_TYPE"] = "sqlite"
os.environ["SQLITE_DB_PATH"] = "./evrmore_auth.db"
os.environ["JWT_SECRET"] = "evrmore-auth-test-secret-key"

# Import after setting environment variables
from evrmore_authentication.db import init_db
from sqlalchemy import text
from evrmore_authentication.db import engine

def main():
    """Initialize the database with SQLite."""
    print("Forcing SQLite configuration...")
    print(f"SQLite DB Path: {os.environ['SQLITE_DB_PATH']}")
    
    # Initialize the database
    print("Initializing database...")
    init_db()
    
    # Test database connection
    print("Testing database connection...")
    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1"))
        row = result.fetchone()
        if row and row[0] == 1:
            print("Database connection successful!")
        else:
            print("Database connection test failed.")
    
    print("Done! You can now run the API server with:")
    print("evrmore-auth-api")

if __name__ == "__main__":
    main() 