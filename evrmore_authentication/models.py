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