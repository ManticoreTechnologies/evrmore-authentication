import os
import sqlite3
import logging
import json
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional, Union
from pathlib import Path

DATABASE_FILE = os.environ.get('EVRMORE_AUTH_DB', 'evrmore_auth.db')
DEBUG_MODE = os.environ.get('EVRMORE_AUTH_DEBUG', '').lower() in ('true', '1', 'yes')

logger = logging.getLogger("evrmore-auth-db")
if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

class SqliteManager:
    """Manages SQLite database for Evrmore authentication data."""
    
    def __init__(self, db_path: str = None):
        """Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or DATABASE_FILE
        self.create_tables_if_not_exist()
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper settings."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
        
    def create_tables_if_not_exist(self) -> None:
        """Create necessary tables if they don't exist."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            evrmore_address TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        )
        ''')
        
        # Sessions table (for authentication sessions)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_active_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        # Challenges table (for auth challenges)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            evrmore_address TEXT NOT NULL,
            challenge_text TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT,
            is_used INTEGER DEFAULT 0
        )
        ''')
        
        # OAuth clients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS oauth_clients (
            id TEXT PRIMARY KEY,
            client_id TEXT UNIQUE NOT NULL,
            client_secret TEXT NOT NULL,
            client_name TEXT,
            client_uri TEXT,
            redirect_uris TEXT,
            allowed_response_types TEXT,
            allowed_scopes TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
        ''')
        
        # OAuth authorization codes table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_used INTEGER DEFAULT 0,
            FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        # OAuth tokens table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id TEXT PRIMARY KEY,
            access_token TEXT UNIQUE NOT NULL,
            refresh_token TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            access_token_expires_at TEXT NOT NULL,
            refresh_token_expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            revoked_at TEXT,
            FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        conn.commit()
        conn.close()
        
    def execute(self, query: str, params: Tuple = ()) -> bool:
        """Execute a query that doesn't return results.
        
        Args:
            query: SQL query to execute
            params: Parameters for the query
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Database error: {str(e)}")
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
            return False
            
    def query(self, query: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        """Execute a query and return results as a list of dictionaries.
        
        Args:
            query: SQL query to execute
            params: Parameters for the query
            
        Returns:
            List of dictionaries with results, empty list if no results or error
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # Convert rows to dictionaries
            results = []
            for row in cursor.fetchall():
                results.append({key: row[key] for key in row.keys()})
                
            conn.close()
            return results
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Database error: {str(e)}")
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
            return []
    
    def exec_many(self, query: str, params_list: List[Tuple]) -> bool:
        """Execute a query multiple times with different parameters.
        
        Args:
            query: SQL query to execute
            params_list: List of parameter tuples for the query
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Database error: {str(e)}")
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params_list}")
            return False
            
    def clear_expired_challenges(self) -> int:
        """Clear expired challenges from the database.
        
        Returns:
            Number of records deleted
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            
            # Delete expired unused challenges
            cursor.execute(
                "DELETE FROM challenges WHERE expires_at < ? AND is_used = 0",
                (now,)
            )
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if DEBUG_MODE and deleted_count > 0:
                logger.debug(f"Cleared {deleted_count} expired challenges")
                
            return deleted_count
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Error clearing expired challenges: {str(e)}")
            return 0
    
    def clear_expired_sessions(self) -> int:
        """Clear expired sessions from the database.
        
        Returns:
            Number of records deleted
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            
            # Delete expired sessions (active and inactive)
            cursor.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (now,)
            )
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if DEBUG_MODE and deleted_count > 0:
                logger.debug(f"Cleared {deleted_count} expired sessions")
                
            return deleted_count
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Error clearing expired sessions: {str(e)}")
            return 0
    
    def clear_expired_oauth_codes(self) -> int:
        """Clear expired OAuth authorization codes from the database.
        
        Returns:
            Number of records deleted
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            
            # Delete expired codes (used and unused)
            cursor.execute(
                "DELETE FROM oauth_authorization_codes WHERE expires_at < ?",
                (now,)
            )
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if DEBUG_MODE and deleted_count > 0:
                logger.debug(f"Cleared {deleted_count} expired OAuth authorization codes")
                
            return deleted_count
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Error clearing expired OAuth authorization codes: {str(e)}")
            return 0
    
    def clear_expired_oauth_tokens(self) -> int:
        """Clear expired OAuth tokens from the database.
        
        Returns:
            Number of records deleted
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            
            # Delete expired tokens (active and inactive)
            # A token is considered expired when both access and refresh tokens are expired
            cursor.execute(
                "DELETE FROM oauth_tokens WHERE access_token_expires_at < ? AND refresh_token_expires_at < ?",
                (now, now)
            )
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if DEBUG_MODE and deleted_count > 0:
                logger.debug(f"Cleared {deleted_count} expired OAuth tokens")
                
            return deleted_count
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"Error clearing expired OAuth tokens: {str(e)}")
            return 0
    
    def maintenance(self) -> Dict[str, int]:
        """Perform database maintenance:
        - Clear expired challenges
        - Clear expired sessions
        - Clear expired OAuth codes
        - Clear expired OAuth tokens
        
        Returns:
            Dictionary with counts of deleted records by type
        """
        challenges = self.clear_expired_challenges()
        sessions = self.clear_expired_sessions()
        oauth_codes = self.clear_expired_oauth_codes()
        oauth_tokens = self.clear_expired_oauth_tokens()
        
        return {
            "challenges": challenges,
            "sessions": sessions,
            "oauth_codes": oauth_codes,
            "oauth_tokens": oauth_tokens,
            "total": challenges + sessions + oauth_codes + oauth_tokens
        } 