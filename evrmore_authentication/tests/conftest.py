"""
Pytest configuration file for Evrmore Authentication tests.

This file contains fixtures that can be used across all test files.
"""

import os
import pytest
import tempfile
import datetime
import uuid
import sqlite3
from unittest.mock import patch, MagicMock
from evrmore_authentication import EvrmoreAuth
from evrmore_authentication.auth import EvrmoreAuth
from evrmore_authentication.models import User, Challenge, Session, SQLiteManager

@pytest.fixture(autouse=True)
def patch_sqlite_connection():
    """
    Patch the SQLite connection to use an in-memory database.
    This is applied to all tests automatically.
    """
    # Create an in-memory SQLite database
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    
    # Initialize the database schema
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            evrmore_address TEXT UNIQUE,
            username TEXT,
            email TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT,
            last_login TEXT
        );
        
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            challenge_text TEXT UNIQUE,
            expires_at TEXT,
            used INTEGER DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            token TEXT UNIQUE,
            expires_at TEXT,
            created_at TEXT,
            is_active INTEGER DEFAULT 1,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS oauth_clients (
            id TEXT PRIMARY KEY,
            client_id TEXT UNIQUE,
            client_secret TEXT,
            client_name TEXT,
            client_uri TEXT,
            redirect_uris TEXT,
            allowed_scopes TEXT,
            allowed_response_types TEXT,
            created_at TEXT,
            updated_at TEXT,
            is_active INTEGER DEFAULT 1,
            created_by TEXT
        );
        
        CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE,
            client_id TEXT,
            user_id TEXT,
            redirect_uri TEXT,
            scope TEXT,
            expires_at TEXT,
            created_at TEXT,
            is_used INTEGER DEFAULT 0,
            FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id TEXT PRIMARY KEY,
            access_token TEXT UNIQUE,
            refresh_token TEXT UNIQUE,
            client_id TEXT,
            user_id TEXT,
            scope TEXT,
            access_token_expires_at TEXT,
            refresh_token_expires_at TEXT,
            created_at TEXT,
            is_active INTEGER DEFAULT 1,
            revoked_at TEXT,
            FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)
    
    # Patch the SQLiteManager class to use our in-memory connection
    with patch('evrmore_authentication.models.sqlite3.connect') as mock_connect:
        mock_connect.return_value = conn
        yield conn

@pytest.fixture
def temp_db_path():
    """Create a temporary database file path."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    os.unlink(path)

@pytest.fixture
def auth():
    """Create an EvrmoreAuth instance with debug mode."""
    return EvrmoreAuth(
        jwt_secret="test_secret",
        jwt_algorithm="HS256",
        debug=True
    )

@pytest.fixture
def test_user():
    """Create a test user."""
    user_id = str(uuid.uuid4())
    test_address = f"E{uuid.uuid4().hex[:34]}"  # Create a plausible address
    
    user = User(
        id=user_id,
        evrmore_address=test_address,
        username="test_user",
        email="test@example.com"
    )
    
    # Return without saving to DB - we'll mock the database interactions
    return user

@pytest.fixture
def test_challenge(test_user):
    """Create a test challenge."""
    challenge_id = str(uuid.uuid4())
    challenge_text = f"Sign this message to authenticate with Evrmore: {test_user.evrmore_address}:{int(datetime.datetime.utcnow().timestamp())}:{uuid.uuid4().hex[:16]}"
    
    challenge = Challenge(
        id=challenge_id,
        user_id=test_user.id,
        challenge_text=challenge_text,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        used=False
    )
    
    return challenge

@pytest.fixture
def test_signature():
    """Create a test signature."""
    return f"IC5MU2AW3E6Kt5noplyBkLXVLSgVHJELy16xw+chbJNNHSVaIZ1uNXhna804o5S09v3jlNjJ8LoNkQZsPN9334M="

@pytest.fixture
def test_session(test_user):
    """Create a test session."""
    session_id = str(uuid.uuid4())
    token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{uuid.uuid4().hex}.{uuid.uuid4().hex[:43]}="
    
    session = Session(
        id=session_id,
        user_id=test_user.id,
        token=token,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        is_active=True
    )
    
    return session 