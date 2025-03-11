"""Data models for Evrmore Authentication using Redis.

This module provides Redis-compatible data models that maintain the same interface
as the original SQLAlchemy models but use Redis for storage instead.
"""

import uuid
import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union

# No longer using SQLAlchemy
# These are dataclasses that mimic the original models

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
    
    # Virtual relationships - these will be loaded lazily
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
    
    # Virtual relationship - will be loaded lazily
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
        
        # Remove user field
        if "user" in data:
            del data["user"]
        
        return cls(**data)
    
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
    
    # Virtual relationship - will be loaded lazily
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
        
        # Remove user field
        if "user" in data:
            del data["user"]
        
        return cls(**data)
    
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
    
    @property
    def is_expired(self):
        """Check if the session is expired."""
        return datetime.datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<Session(id={self.id}, user_id={self.user_id}, expired={self.is_expired})>" 