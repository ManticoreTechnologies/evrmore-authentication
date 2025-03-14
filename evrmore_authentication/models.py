"""Data models for Evrmore Authentication using SQLite.

This module provides SQLite-compatible data models for the Evrmore Authentication system.
"""

import uuid
import datetime
import sqlite3
import os
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
import secrets
import logging

class SQLiteManager:
    """Manager for SQLite database operations."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SQLiteManager, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self):
        if not self.initialized:
            db_path = os.environ.get('SQLITE_DB_PATH', './data/evrmore_auth.db')
            
            # Create data directory if it doesn't exist
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._create_tables()
            self.initialized = True
    
    def _create_tables(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Create User table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            evrmore_address TEXT UNIQUE NOT NULL,
            username TEXT,
            email TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
        ''')
        
        # Create Challenge table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            challenge_text TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create Session table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create OAuth 2.0 Client table
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
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        ''')
        
        # Create OAuth 2.0 Authorization Code table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            scope TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create OAuth 2.0 Token table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id TEXT PRIMARY KEY,
            access_token TEXT UNIQUE NOT NULL,
            refresh_token TEXT UNIQUE,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            access_token_expires_at TEXT NOT NULL,
            refresh_token_expires_at TEXT,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            revoked_at TEXT,
            FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        self.conn.commit()
    
    def execute(self, query, params=None):
        """Execute an SQL query and return the cursor."""
        cursor = self.conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        self.conn.commit()
        return cursor
    
    def fetchone(self, query, params=None):
        """Execute a query and fetch one result."""
        cursor = self.execute(query, params)
        return cursor.fetchone()
    
    def fetchall(self, query, params=None):
        """Execute a query and fetch all results."""
        cursor = self.execute(query, params)
        return cursor.fetchall()

@dataclass
class User:
    """User model representing an authenticated wallet owner."""
    
    id: str
    evrmore_address: str
    username: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    last_login: Optional[datetime.datetime] = None
    
    # Virtual relationships - these will be loaded on demand
    challenges: List["Challenge"] = field(default_factory=list)
    sessions: List["Session"] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data):
        """Create a User from a dictionary."""
        if not data:
            return None
            
        # Convert string timestamps to datetime objects
        created_at = data.get("created_at")
        if created_at and isinstance(created_at, str):
            data["created_at"] = datetime.datetime.fromisoformat(created_at)
            
        last_login = data.get("last_login")
        if last_login and isinstance(last_login, str):
            data["last_login"] = datetime.datetime.fromisoformat(last_login)
        
        return cls(**data)
    
    @classmethod
    def from_row(cls, row):
        """Create a User from a database row."""
        if not row:
            return None
            
        data = dict(row)
        return cls.from_dict(data)
    
    @classmethod
    def create(cls, evrmore_address, username=None, email=None):
        """Create a new user with the provided Evrmore address.
        
        Args:
            evrmore_address: User's Evrmore wallet address
            username: Optional username
            email: Optional email address
            
        Returns:
            Newly created User object
        """
        user_id = str(uuid.uuid4())
        user = cls(
            id=user_id,
            evrmore_address=evrmore_address,
            username=username,
            email=email,
            is_active=True,
            created_at=datetime.datetime.utcnow()
        )
        user.save()
        return user
    
    def to_dict(self):
        """Convert User to a dictionary."""
        return {
            "id": str(self.id),
            "evrmore_address": self.evrmore_address,
            "username": self.username,
            "email": self.email,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }
    
    def save(self):
        """Save user to database."""
        db = SQLiteManager()
        user_dict = self.to_dict()
        
        # Check if user exists
        existing = db.fetchone("SELECT * FROM users WHERE id = ?", (self.id,))
        
        if existing:
            # Update existing user
            db.execute(
                """UPDATE users SET 
                evrmore_address = ?, username = ?, email = ?, is_active = ?,
                created_at = ?, last_login = ? WHERE id = ?""",
                (self.evrmore_address, self.username, self.email, 
                 1 if self.is_active else 0,
                 user_dict["created_at"], user_dict["last_login"], self.id)
            )
        else:
            # Insert new user
            db.execute(
                """INSERT INTO users 
                (id, evrmore_address, username, email, is_active, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.evrmore_address, self.username, self.email, 
                 1 if self.is_active else 0,
                 user_dict["created_at"], user_dict["last_login"])
            )
    
    @classmethod
    def get_by_id(cls, user_id):
        """Get user by ID."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
        return cls.from_row(row)
    
    @classmethod
    def get_by_address(cls, address):
        """Get user by Evrmore address."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM users WHERE evrmore_address = ?", (address,))
        return cls.from_row(row)
    
    def __repr__(self):
        return f"<User(id={self.id}, evrmore_address={self.evrmore_address})>"

@dataclass
class Challenge:
    """Challenge model for storing authentication challenges."""
    
    id: str
    user_id: str
    challenge_text: str
    expires_at: datetime.datetime
    used: bool = False
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    
    # Virtual relationship - will be loaded on demand
    user: Optional[User] = None
    
    @classmethod
    def from_dict(cls, data):
        """Create a Challenge from a dictionary."""
        if not data:
            return None
            
        # Convert string timestamps to datetime objects
        created_at = data.get("created_at")
        if created_at and isinstance(created_at, str):
            data["created_at"] = datetime.datetime.fromisoformat(created_at)
            
        expires_at = data.get("expires_at")
        if expires_at and isinstance(expires_at, str):
            data["expires_at"] = datetime.datetime.fromisoformat(expires_at)
        
        # Handle boolean conversion
        if "used" in data and isinstance(data["used"], int):
            data["used"] = bool(data["used"])
            
        # Remove user field if present
        if "user" in data:
            del data["user"]
        
        return cls(**data)
    
    @classmethod
    def from_row(cls, row):
        """Create a Challenge from a database row."""
        if not row:
            return None
            
        data = dict(row)
        return cls.from_dict(data)
    
    def to_dict(self):
        """Convert Challenge to a dictionary."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "challenge_text": self.challenge_text,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "used": self.used
        }
    
    def save(self):
        """Save challenge to database."""
        db = SQLiteManager()
        challenge_dict = self.to_dict()
        
        # Check if challenge exists
        existing = db.fetchone("SELECT * FROM challenges WHERE id = ?", (self.id,))
        
        if existing:
            # Update existing challenge
            db.execute(
                """UPDATE challenges SET 
                user_id = ?, challenge_text = ?, expires_at = ?, used = ?,
                created_at = ? WHERE id = ?""",
                (self.user_id, self.challenge_text, challenge_dict["expires_at"], 
                 1 if self.used else 0, challenge_dict["created_at"], self.id)
            )
        else:
            # Insert new challenge
            db.execute(
                """INSERT INTO challenges 
                (id, user_id, challenge_text, expires_at, used, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (self.id, self.user_id, self.challenge_text, 
                 challenge_dict["expires_at"], 1 if self.used else 0, 
                 challenge_dict["created_at"])
            )
    
    @classmethod
    def get_by_id(cls, challenge_id):
        """Get challenge by ID."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM challenges WHERE id = ?", (challenge_id,))
        return cls.from_row(row)
    
    @classmethod
    def get_by_text(cls, challenge_text):
        """Get challenge by text."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM challenges WHERE challenge_text = ?", (challenge_text,))
        return cls.from_row(row)
    
    @classmethod
    def get_by_user_id(cls, user_id):
        """Get challenges for a user."""
        db = SQLiteManager()
        rows = db.fetchall("SELECT * FROM challenges WHERE user_id = ?", (user_id,))
        return [cls.from_row(row) for row in rows]
    
    @property
    def is_expired(self):
        """Check if the challenge is expired."""
        return datetime.datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<Challenge(id={self.id}, user_id={self.user_id}, expired={self.is_expired})>"

@dataclass
class Session:
    """Session model for storing user authentication sessions."""
    
    id: str
    user_id: str
    token: str
    expires_at: datetime.datetime
    is_active: bool = True
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Virtual relationship - will be loaded on demand
    user: Optional[User] = None
    
    @classmethod
    def from_dict(cls, data):
        """Create a Session from a dictionary."""
        if not data:
            return None
            
        # Convert string timestamps to datetime objects
        created_at = data.get("created_at")
        if created_at and isinstance(created_at, str):
            data["created_at"] = datetime.datetime.fromisoformat(created_at)
            
        expires_at = data.get("expires_at")
        if expires_at and isinstance(expires_at, str):
            data["expires_at"] = datetime.datetime.fromisoformat(expires_at)
        
        # Handle boolean conversion
        if "is_active" in data and isinstance(data["is_active"], int):
            data["is_active"] = bool(data["is_active"])
            
        # Remove user field if present
        if "user" in data:
            del data["user"]
        
        return cls(**data)
    
    @classmethod
    def from_row(cls, row):
        """Create a Session from a database row."""
        if not row:
            return None
            
        data = dict(row)
        return cls.from_dict(data)
    
    def to_dict(self):
        """Convert Session to a dictionary."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "token": self.token,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent
        }
    
    def save(self):
        """Save session to database."""
        db = SQLiteManager()
        session_dict = self.to_dict()
        
        # Check if session exists
        existing = db.fetchone("SELECT * FROM sessions WHERE id = ?", (self.id,))
        
        if existing:
            # Update existing session
            db.execute(
                """UPDATE sessions SET 
                user_id = ?, token = ?, expires_at = ?, is_active = ?,
                created_at = ?, ip_address = ?, user_agent = ? WHERE id = ?""",
                (self.user_id, self.token, session_dict["expires_at"], 
                 1 if self.is_active else 0, session_dict["created_at"],
                 self.ip_address, self.user_agent, self.id)
            )
        else:
            # Insert new session
            db.execute(
                """INSERT INTO sessions 
                (id, user_id, token, expires_at, is_active, created_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.user_id, self.token, session_dict["expires_at"], 
                 1 if self.is_active else 0, session_dict["created_at"],
                 self.ip_address, self.user_agent)
            )
    
    @classmethod
    def get_by_id(cls, session_id):
        """Get session by ID."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM sessions WHERE id = ?", (session_id,))
        return cls.from_row(row)
    
    @classmethod
    def get_by_token(cls, token):
        """Get session by token."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM sessions WHERE token = ?", (token,))
        return cls.from_row(row)
    
    @classmethod
    def get_by_user_id(cls, user_id):
        """Get sessions for a user."""
        db = SQLiteManager()
        rows = db.fetchall("SELECT * FROM sessions WHERE user_id = ?", (user_id,))
        return [cls.from_row(row) for row in rows]
    
    @property
    def is_expired(self):
        """Check if the session is expired."""
        return datetime.datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<Session(id={self.id}, user_id={self.user_id}, expired={self.is_expired})>"

@dataclass
class OAuthClient:
    """OAuth 2.0 client application."""
    client_name: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    client_uri: Optional[str] = None
    redirect_uris: Union[str, List[str]] = ""  # List or comma-separated list of allowed redirect URIs
    allowed_response_types: Union[str, List[str]] = "code"  # List or comma-separated list of allowed response types
    allowed_scopes: Union[str, List[str]] = "profile"  # List or comma-separated list of allowed scopes
    created_by: Optional[str] = None  # Owner of this client, if applicable
    created_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.utcnow())
    updated_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.utcnow())
    is_active: bool = True
    
    def __post_init__(self):
        """Process fields after initialization."""
        # Convert string redirect_uris to list if needed
        if isinstance(self.redirect_uris, str) and self.redirect_uris:
            self.redirect_uris = self.redirect_uris.split(',')
        elif not self.redirect_uris:
            self.redirect_uris = []
            
        # Convert string allowed_response_types to list if needed
        if isinstance(self.allowed_response_types, str) and self.allowed_response_types:
            self.allowed_response_types = self.allowed_response_types.split(',')
        elif not self.allowed_response_types:
            self.allowed_response_types = ["code"]
            
        # Convert string allowed_scopes to list if needed
        if isinstance(self.allowed_scopes, str) and self.allowed_scopes:
            self.allowed_scopes = self.allowed_scopes.split(',')
        elif not self.allowed_scopes:
            self.allowed_scopes = ["profile"]
    
    @classmethod
    def create(cls, client_name: str, redirect_uris: Union[str, List[str]], 
               created_by: Optional[str] = None, 
               allowed_scopes: Union[str, List[str]] = None,
               allowed_response_types: Union[str, List[str]] = None,
               client_uri: Optional[str] = None) -> 'OAuthClient':
        """Create a new OAuth client.
        
        Args:
            client_name: Name of the client application
            redirect_uris: List of allowed redirect URIs or comma-separated string
            created_by: ID of the user who created this client (optional)
            allowed_scopes: List of allowed scopes or comma-separated string (default: ["profile"])
            allowed_response_types: List of allowed response types or comma-separated string (default: ["code"])
            client_uri: URI of the client application (optional)
            
        Returns:
            OAuthClient: The newly created client
        """
        db = SQLiteManager()
        client_id = str(uuid.uuid4())
        client_secret = secrets.token_urlsafe(32)
        now = datetime.datetime.utcnow()
        
        # Process redirect_uris
        redirect_uris_str = ','.join(redirect_uris) if isinstance(redirect_uris, list) else redirect_uris
        
        # Process allowed_response_types
        if allowed_response_types is None:
            allowed_response_types = ["code"]
        allowed_response_types_str = ','.join(allowed_response_types) if isinstance(allowed_response_types, list) else allowed_response_types
        
        # Process allowed_scopes
        if allowed_scopes is None:
            allowed_scopes = ["profile"]
        allowed_scopes_str = ','.join(allowed_scopes) if isinstance(allowed_scopes, list) else allowed_scopes
        
        client = cls(
            id=str(uuid.uuid4()),
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name,
            client_uri=client_uri,
            redirect_uris=redirect_uris,
            allowed_response_types=allowed_response_types,
            allowed_scopes=allowed_scopes,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            is_active=True
        )
        
        # Insert into database
        db.execute(
            """INSERT INTO oauth_clients 
            (id, client_id, client_secret, client_name, client_uri, redirect_uris, 
            allowed_response_types, allowed_scopes, created_by, created_at, updated_at, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (client.id, client.client_id, client.client_secret, client.client_name, 
             client.client_uri, redirect_uris_str, allowed_response_types_str, 
             allowed_scopes_str, client.created_by, 
             client.created_at.isoformat(), client.updated_at.isoformat(), 1)
        )
        
        return client
    
    @classmethod
    def get_by_client_id(cls, client_id: str) -> Optional['OAuthClient']:
        """Get a client by client_id.
        
        Args:
            client_id: The client ID to look up
            
        Returns:
            Optional[OAuthClient]: The client if found, None otherwise
        """
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,))
        
        if not row:
            return None
            
        created_at = datetime.datetime.fromisoformat(row['created_at']) if row['created_at'] else datetime.datetime.utcnow()
        updated_at = datetime.datetime.fromisoformat(row['updated_at']) if row['updated_at'] else created_at
        
        return cls(
            id=row['id'],
            client_id=row['client_id'],
            client_secret=row['client_secret'],
            client_name=row['client_name'],
            client_uri=row['client_uri'],
            redirect_uris=row['redirect_uris'],
            allowed_response_types=row['allowed_response_types'],
            allowed_scopes=row['allowed_scopes'],
            created_by=row['created_by'],
            created_at=created_at,
            updated_at=updated_at,
            is_active=bool(row['is_active']) if 'is_active' in row.keys() else True
        )
    
    def verify_client_secret(self, secret: str) -> bool:
        """Verify a client secret.
        
        Args:
            secret: The secret to verify
            
        Returns:
            bool: True if the secret is valid
        """
        return secrets.compare_digest(self.client_secret, secret)
    
    def verify_redirect_uri(self, redirect_uri: str) -> bool:
        """Verify a redirect URI is allowed for this client.
        
        Args:
            redirect_uri: The redirect URI to verify
            
        Returns:
            bool: True if the redirect URI is allowed
        """
        return redirect_uri in self.redirect_uris
    
    def verify_scope(self, scope: str) -> bool:
        """Verify a scope is allowed for this client.
        
        Args:
            scope: The scope to verify
            
        Returns:
            bool: True if the scope is allowed
        """
        requested_scopes = scope.split() if scope else []
        for s in requested_scopes:
            if s not in self.allowed_scopes:
                return False
        return True
    
    def verify_response_type(self, response_type: str) -> bool:
        """Verify a response type is allowed for this client.
        
        Args:
            response_type: The response type to verify
            
        Returns:
            bool: True if the response type is allowed
        """
        return response_type in self.allowed_response_types

    def save(self) -> bool:
        """Save changes to database."""
        db = SQLiteManager()
        self.updated_at = datetime.datetime.utcnow()
        
        # Convert lists to strings for storage
        redirect_uris_str = ','.join(self.redirect_uris) if isinstance(self.redirect_uris, list) else self.redirect_uris
        allowed_response_types_str = ','.join(self.allowed_response_types) if isinstance(self.allowed_response_types, list) else self.allowed_response_types
        allowed_scopes_str = ','.join(self.allowed_scopes) if isinstance(self.allowed_scopes, list) else self.allowed_scopes
        
        # Check if client exists
        row = db.fetchone("SELECT id FROM oauth_clients WHERE id = ?", (self.id,))
        
        if row:
            # Update
            return bool(db.execute(
                """UPDATE oauth_clients SET 
                client_id = ?, client_secret = ?, client_name = ?, client_uri = ?, redirect_uris = ?,
                allowed_response_types = ?, allowed_scopes = ?, created_by = ?, created_at = ?, 
                updated_at = ?, is_active = ? WHERE id = ?""",
                (self.client_id, self.client_secret, self.client_name, self.client_uri, 
                 redirect_uris_str, allowed_response_types_str, allowed_scopes_str, 
                 self.created_by, self.created_at.isoformat(), self.updated_at.isoformat(), 
                 int(self.is_active), self.id)
            ))
        else:
            # Insert
            return bool(db.execute(
                """INSERT INTO oauth_clients 
                (id, client_id, client_secret, client_name, client_uri, redirect_uris, 
                allowed_response_types, allowed_scopes, created_by, created_at, updated_at, is_active) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.client_id, self.client_secret, self.client_name, 
                 self.client_uri, redirect_uris_str, allowed_response_types_str, 
                 allowed_scopes_str, self.created_by, self.created_at.isoformat(), 
                 self.updated_at.isoformat(), int(self.is_active))
            ))

@dataclass
class OAuthAuthorizationCode:
    """OAuth 2.0 authorization code."""
    id: str
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    expires_at: datetime.datetime
    is_used: bool = False
    created_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.utcnow())
    
    @classmethod
    def get_by_code(cls, code: str) -> Optional['OAuthAuthorizationCode']:
        """Get an authorization code by code.
        
        Args:
            code: The authorization code to look up
            
        Returns:
            Optional[OAuthAuthorizationCode]: The authorization code if found and not expired, None otherwise
        """
        logger = logging.getLogger(__name__)
        logger.info(f"Looking up authorization code: {code}")
        
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM oauth_authorization_codes WHERE code = ?", (code,))
        
        if not row:
            logger.error(f"Authorization code not found: {code}")
            return None
            
        logger.info(f"Authorization code found: {code}, id={row['id']}, client_id={row['client_id']}, user_id={row['user_id']}")
            
        expires_at = datetime.datetime.fromisoformat(row['expires_at'])
        created_at = datetime.datetime.fromisoformat(row['created_at'])
        
        auth_code = cls(
            id=row['id'],
            code=row['code'],
            client_id=row['client_id'],
            user_id=row['user_id'],
            redirect_uri=row['redirect_uri'],
            scope=row['scope'],
            expires_at=expires_at,
            is_used=bool(row['used']),
            created_at=created_at
        )
        
        logger.info(f"Authorization code object created: used={auth_code.is_used}, expired={auth_code.is_expired()}")
        return auth_code
    
    def is_expired(self) -> bool:
        """Check if the authorization code is expired.
        
        Returns:
            bool: True if the code is expired
        """
        return datetime.datetime.utcnow() > self.expires_at
    
    def is_valid(self, client_id: str, redirect_uri: str) -> bool:
        """Check if the authorization code is valid for the given client and redirect URI.
        
        Args:
            client_id: The client ID to check
            redirect_uri: The redirect URI to check
            
        Returns:
            bool: True if the code is valid for the given client and redirect URI
        """
        logger = logging.getLogger(__name__)
        
        # Check if already used
        if self.is_used:
            logger.error(f"Auth code {self.code} has already been used")
            return False
            
        # Check if expired
        if self.is_expired():
            logger.error(f"Auth code {self.code} has expired. Expires at: {self.expires_at}, Now: {datetime.datetime.utcnow()}")
            return False
            
        # Check client ID
        if self.client_id != client_id:
            logger.error(f"Client ID mismatch: Expected {self.client_id}, got {client_id}")
            return False
            
        # Check redirect URI
        if self.redirect_uri != redirect_uri:
            logger.error(f"Redirect URI mismatch: Expected {self.redirect_uri}, got {redirect_uri}")
            return False
            
        logger.info(f"Auth code {self.code} is valid for client {client_id} and redirect URI {redirect_uri}")
        return True
    
    def use(self) -> bool:
        """Mark the authorization code as used.
        
        Returns:
            bool: True if successful
        """
        self.is_used = True
        return self.save()
    
    def save(self) -> bool:
        """Save changes to database.
        
        Returns:
            bool: True if successful
        """
        db = SQLiteManager()
        
        # Check if code exists
        row = db.fetchone("SELECT id FROM oauth_authorization_codes WHERE id = ?", (self.id,))
        
        if row:
            # Update
            return bool(db.execute(
                """UPDATE oauth_authorization_codes SET 
                code = ?, client_id = ?, user_id = ?, redirect_uri = ?, 
                scope = ?, expires_at = ?, used = ?, created_at = ? 
                WHERE id = ?""",
                (self.code, self.client_id, self.user_id, self.redirect_uri, 
                 self.scope, self.expires_at.isoformat(), int(self.is_used), 
                 self.created_at.isoformat(), self.id)
            ))
        else:
            # Insert
            return bool(db.execute(
                """INSERT INTO oauth_authorization_codes 
                (id, code, client_id, user_id, redirect_uri, scope, expires_at, used, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.code, self.client_id, self.user_id, self.redirect_uri, 
                 self.scope, self.expires_at.isoformat(), int(self.is_used), 
                 self.created_at.isoformat())
            ))

@dataclass
class OAuthToken:
    """OAuth 2.0 token."""
    id: str
    access_token: str
    refresh_token: str
    client_id: str
    user_id: str
    scope: str
    access_token_expires_at: datetime.datetime
    refresh_token_expires_at: datetime.datetime
    created_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.utcnow())
    is_active: bool = True
    revoked_at: Optional[datetime.datetime] = None
    
    @classmethod
    def get_by_access_token(cls, access_token: str) -> Optional['OAuthToken']:
        """Get a token by access token.
        
        Args:
            access_token: The access token to look up
            
        Returns:
            Optional[OAuthToken]: The token if found, None otherwise
        """
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM oauth_tokens WHERE access_token = ?", (access_token,))
        
        if not row:
            return None
            
        return cls._from_row(row)
    
    @classmethod
    def get_by_refresh_token(cls, refresh_token: str) -> Optional['OAuthToken']:
        """Get a token by refresh token.
        
        Args:
            refresh_token: The refresh token to look up
            
        Returns:
            Optional[OAuthToken]: The token if found, None otherwise
        """
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM oauth_tokens WHERE refresh_token = ?", (refresh_token,))
        
        if not row:
            return None
            
        return cls._from_row(row)
    
    @classmethod
    def _from_row(cls, row: Dict[str, Any]) -> 'OAuthToken':
        """Create an OAuthToken from a database row.
        
        Args:
            row: Database row
            
        Returns:
            OAuthToken: Token object
        """
        # Convert sqlite3.Row to dict if needed
        data = dict(row)
        
        access_token_expires_at = datetime.datetime.fromisoformat(data['access_token_expires_at'])
        refresh_token_expires_at = datetime.datetime.fromisoformat(data['refresh_token_expires_at'])
        created_at = datetime.datetime.fromisoformat(data['created_at'])
        
        revoked_at = None
        if 'revoked_at' in data and data['revoked_at']:
            revoked_at = datetime.datetime.fromisoformat(data['revoked_at'])
        
        return cls(
            id=data['id'],
            access_token=data['access_token'],
            refresh_token=data['refresh_token'],
            client_id=data['client_id'],
            user_id=data['user_id'],
            scope=data['scope'],
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
            created_at=created_at,
            is_active=bool(data['is_active'] if 'is_active' in data else 1),
            revoked_at=revoked_at
        )
    
    def is_access_token_expired(self) -> bool:
        """Check if the access token is expired.
        
        Returns:
            bool: True if the access token is expired
        """
        return datetime.datetime.utcnow() > self.access_token_expires_at
    
    def is_refresh_token_expired(self) -> bool:
        """Check if the refresh token is expired.
        
        Returns:
            bool: True if the refresh token is expired
        """
        return datetime.datetime.utcnow() > self.refresh_token_expires_at
    
    def revoke(self) -> bool:
        """Revoke the token.
        
        Returns:
            bool: True if successful
        """
        self.is_active = False
        self.revoked_at = datetime.datetime.utcnow()
        return self.save()
    
    def save(self) -> bool:
        """Save changes to database.
        
        Returns:
            bool: True if successful
        """
        db = SQLiteManager()
        
        # Check if token exists
        row = db.fetchone("SELECT id FROM oauth_tokens WHERE id = ?", (self.id,))
        
        if row:
            # Update
            return bool(db.execute(
                """UPDATE oauth_tokens SET 
                access_token = ?, refresh_token = ?, client_id = ?, user_id = ?, 
                scope = ?, access_token_expires_at = ?, refresh_token_expires_at = ?, 
                created_at = ?, is_active = ?, revoked_at = ? 
                WHERE id = ?""",
                (self.access_token, self.refresh_token, self.client_id, self.user_id, 
                 self.scope, self.access_token_expires_at.isoformat(), 
                 self.refresh_token_expires_at.isoformat(), self.created_at.isoformat(), 
                 int(self.is_active), 
                 self.revoked_at.isoformat() if self.revoked_at else None, 
                 self.id)
            ))
        else:
            # Insert
            return bool(db.execute(
                """INSERT INTO oauth_tokens 
                (id, access_token, refresh_token, client_id, user_id, scope, 
                access_token_expires_at, refresh_token_expires_at, created_at, is_active, revoked_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.access_token, self.refresh_token, self.client_id, 
                 self.user_id, self.scope, self.access_token_expires_at.isoformat(), 
                 self.refresh_token_expires_at.isoformat(), self.created_at.isoformat(), 
                 int(self.is_active), 
                 self.revoked_at.isoformat() if self.revoked_at else None)
            ))
    
    @classmethod
    def get_active_by_user_id(cls, user_id: str) -> List['OAuthToken']:
        """Get all active tokens for a user.
        
        Args:
            user_id: The user ID to look up
            
        Returns:
            List[OAuthToken]: List of active tokens
        """
        db = SQLiteManager()
        rows = db.execute(
            "SELECT * FROM oauth_tokens WHERE user_id = ? AND is_active = 1", 
            (user_id,)
        ).fetchall()
        
        tokens = []
        for row in rows:
            tokens.append(cls._from_row(row))
            
        return tokens
    
    @classmethod
    def revoke_all_by_user_id(cls, user_id: str) -> bool:
        """Revoke all active tokens for a user.
        
        Args:
            user_id: The user ID
            
        Returns:
            bool: True if successful
        """
        db = SQLiteManager()
        revoked_at = datetime.datetime.utcnow().isoformat()
        
        return bool(db.execute(
            """UPDATE oauth_tokens SET 
            is_active = 0, revoked_at = ? 
            WHERE user_id = ? AND is_active = 1""",
            (revoked_at, user_id)
        ))

# Utility functions for database maintenance

def cleanup_expired_challenges():
    """Remove expired challenges from the database.
    
    Returns:
        Number of challenges removed
    """
    db = SQLiteManager()
    now = datetime.datetime.utcnow().isoformat()
    
    # First, get the count of expired challenges
    row = db.fetchone("SELECT COUNT(*) as count FROM challenges WHERE expires_at < ?", (now,))
    count = row['count'] if row else 0
    
    # Then delete them
    db.execute("DELETE FROM challenges WHERE expires_at < ?", (now,))
    
    return count
    
def cleanup_expired_sessions():
    """Remove expired sessions from the database.
    
    Returns:
        Number of sessions removed
    """
    db = SQLiteManager()
    now = datetime.datetime.utcnow().isoformat()
    
    # First, get the count of expired sessions
    row = db.fetchone("SELECT COUNT(*) as count FROM sessions WHERE expires_at < ?", (now,))
    count = row['count'] if row else 0
    
    # Then delete them
    db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    
    return count

def inspect_database_tables():
    """Inspect database tables to help with debugging.
    
    Returns:
        Dictionary with table information
    """
    db = SQLiteManager()
    
    # Get tables
    tables = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    table_info = {}
    
    for table in tables:
        table_name = table['name']
        
        # Get column info
        columns = db.fetchall(f"PRAGMA table_info({table_name})")
        column_info = [
            {
                "name": col['name'],
                "type": col['type'],
                "notnull": bool(col['notnull']),
                "pk": bool(col['pk'])
            }
            for col in columns
        ]
        
        # Get row count
        row = db.fetchone(f"SELECT COUNT(*) as count FROM {table_name}")
        row_count = row['count'] if row else 0
        
        table_info[table_name] = {
            "columns": column_info,
            "row_count": row_count
        }
    
    return table_info
    
def get_user_challenges(user_id):
    """Get all challenges for a user.
    
    Args:
        user_id: User ID
        
    Returns:
        List of challenges
    """
    return Challenge.get_by_user_id(user_id)
    
def get_user_sessions(user_id):
    """Get all sessions for a user.
    
    Args:
        user_id: User ID
        
    Returns:
        List of sessions
    """
    return Session.get_by_user_id(user_id)

def check_database_integrity():
    """Check database integrity.
    
    Returns:
        Dictionary with integrity check results
    """
    db = SQLiteManager()
    
    # Run SQLite integrity check
    integrity = db.fetchall("PRAGMA integrity_check")
    integrity_ok = len(integrity) == 1 and integrity[0]['integrity_check'] == 'ok'
    
    # Check for orphaned challenges (user doesn't exist)
    orphaned_challenges_query = """
    SELECT COUNT(*) as count FROM challenges 
    WHERE user_id NOT IN (SELECT id FROM users)
    """
    row = db.fetchone(orphaned_challenges_query)
    orphaned_challenges = row['count'] if row else 0
    
    # Check for orphaned sessions (user doesn't exist)
    orphaned_sessions_query = """
    SELECT COUNT(*) as count FROM sessions 
    WHERE user_id NOT IN (SELECT id FROM users)
    """
    row = db.fetchone(orphaned_sessions_query)
    orphaned_sessions = row['count'] if row else 0
    
    return {
        "integrity_check": "ok" if integrity_ok else "failed",
        "orphaned_challenges": orphaned_challenges,
        "orphaned_sessions": orphaned_sessions
    } 