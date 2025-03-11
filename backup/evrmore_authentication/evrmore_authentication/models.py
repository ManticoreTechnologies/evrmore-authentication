"""Database models for Evrmore Authentication.

This module defines the SQLAlchemy ORM models for the Evrmore Authentication system.
"""

import uuid
import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime,
    Boolean, ForeignKey, Text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .db import Base

class User(Base):
    """User model representing an authenticated wallet owner."""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evrmore_address = Column(String(100), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=True)
    email = Column(String(255), unique=True, index=True, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    challenges = relationship("Challenge", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id={self.id}, evrmore_address='{self.evrmore_address}')>"

class Challenge(Base):
    """Challenge model for storing authentication challenges."""
    
    __tablename__ = "challenges"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    challenge_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="challenges")
    
    def __repr__(self):
        return f"<Challenge(id={self.id}, user_id={self.user_id}, expires_at='{self.expires_at}')>"
    
    @property
    def is_expired(self):
        """Check if the challenge has expired.
        
        Returns:
            bool: True if challenge has expired, False otherwise
        """
        return datetime.datetime.utcnow() > self.expires_at
    
class Session(Base):
    """Session model for storing user authentication sessions."""
    
    __tablename__ = "sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token = Column(String(512), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(512), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<Session(id={self.id}, user_id={self.user_id}, is_active={self.is_active})>"
    
    @property
    def is_expired(self):
        """Check if the session has expired.
        
        Returns:
            bool: True if session has expired, False otherwise
        """
        return datetime.datetime.utcnow() > self.expires_at 