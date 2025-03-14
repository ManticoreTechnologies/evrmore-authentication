#!/usr/bin/env python3
"""
Evrmore Accounts System Example

This script demonstrates how to extend the Evrmore Authentication library
to build a complete accounts system, including user profiles, settings,
and additional functionality.

© 2024 Manticore Technologies - manticore.technology
"""

import os
import sys
import uuid
import datetime
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# Add the parent directory to the path so we can import from the module
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from evrmore_authentication import EvrmoreAuth, User, UserSession
from evrmore_authentication.models import SQLiteManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-accounts-demo")

# Define additional models for the accounts system
@dataclass
class Profile:
    """User profile model."""
    id: str
    user_id: str
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    
    @classmethod
    def get_by_user_id(cls, user_id: str) -> Optional['Profile']:
        """Get profile by user ID."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
        if not row:
            return None
        return cls.from_row(row)
    
    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> 'Profile':
        """Create a profile from a database row."""
        data = dict(row)
        
        # Handle datetime conversion
        for field_name in ["created_at", "updated_at"]:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.datetime.fromisoformat(data[field_name])
        
        return cls(**data)
    
    def save(self) -> None:
        """Save or update profile in the database."""
        db = SQLiteManager()
        
        # Prepare data for database
        now = datetime.datetime.utcnow()
        self.updated_at = now
        
        # Convert datetime objects to ISO format strings
        created_at_str = self.created_at.isoformat()
        updated_at_str = self.updated_at.isoformat()
        
        # Check if profile already exists
        existing = db.fetchone("SELECT id FROM profiles WHERE id = ?", (self.id,))
        
        if existing:
            # Update existing profile
            db.execute(
                """UPDATE profiles SET 
                user_id = ?, display_name = ?, bio = ?, avatar_url = ?,
                created_at = ?, updated_at = ? WHERE id = ?""",
                (self.user_id, self.display_name, self.bio, self.avatar_url,
                 created_at_str, updated_at_str, self.id)
            )
        else:
            # Insert new profile
            db.execute(
                """INSERT INTO profiles 
                (id, user_id, display_name, bio, avatar_url, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.user_id, self.display_name, self.bio, self.avatar_url,
                 created_at_str, updated_at_str)
            )


@dataclass
class UserSetting:
    """User setting model for storing user preferences."""
    id: str
    user_id: str
    setting_key: str
    setting_value: str
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    
    @classmethod
    def get_by_user_and_key(cls, user_id: str, key: str) -> Optional['UserSetting']:
        """Get setting by user ID and key."""
        db = SQLiteManager()
        row = db.fetchone(
            "SELECT * FROM user_settings WHERE user_id = ? AND setting_key = ?", 
            (user_id, key)
        )
        if not row:
            return None
        return cls.from_row(row)
    
    @classmethod
    def get_all_for_user(cls, user_id: str) -> List['UserSetting']:
        """Get all settings for a user."""
        db = SQLiteManager()
        rows = db.fetchall("SELECT * FROM user_settings WHERE user_id = ?", (user_id,))
        return [cls.from_row(row) for row in rows]
    
    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> 'UserSetting':
        """Create a setting from a database row."""
        data = dict(row)
        
        # Handle datetime conversion
        for field_name in ["created_at", "updated_at"]:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.datetime.fromisoformat(data[field_name])
        
        return cls(**data)
    
    def save(self) -> None:
        """Save or update setting in the database."""
        db = SQLiteManager()
        
        # Prepare data for database
        now = datetime.datetime.utcnow()
        self.updated_at = now
        
        # Convert datetime objects to ISO format strings
        created_at_str = self.created_at.isoformat()
        updated_at_str = self.updated_at.isoformat()
        
        # Check if setting already exists for this user and key
        existing = db.fetchone(
            "SELECT id FROM user_settings WHERE user_id = ? AND setting_key = ?", 
            (self.user_id, self.setting_key)
        )
        
        if existing:
            # Update existing setting
            self.id = existing["id"]  # Use existing ID
            db.execute(
                """UPDATE user_settings SET 
                setting_value = ?, updated_at = ? 
                WHERE id = ?""",
                (self.setting_value, updated_at_str, self.id)
            )
        else:
            # Insert new setting
            if not self.id:
                self.id = str(uuid.uuid4())
                
            db.execute(
                """INSERT INTO user_settings 
                (id, user_id, setting_key, setting_value, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (self.id, self.user_id, self.setting_key, self.setting_value,
                 created_at_str, updated_at_str)
            )


# Extend the database manager to include our new tables
class ExtendedSQLiteManager(SQLiteManager):
    """Extended SQLite manager with additional tables for the accounts system."""
    
    def _create_tables(self):
        """Create all tables including the extended ones."""
        # Call parent method to create core tables
        super()._create_tables()
        
        # Create our extended tables
        cursor = self.conn.cursor()
        
        # Create Profile table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            display_name TEXT,
            bio TEXT,
            avatar_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create User Settings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            setting_key TEXT NOT NULL,
            setting_value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        self.conn.commit()


# Extended authentication system with account management features
class AccountSystem(EvrmoreAuth):
    """Extended authentication system with account management."""
    
    def __init__(self, **kwargs):
        """Initialize the account system."""
        super().__init__(**kwargs)
        
        # Replace the SQLiteManager singleton with our extended version
        SQLiteManager._instance = ExtendedSQLiteManager()
        
        logger.info("Initialized Evrmore Accounts System")
    
    def register_user(self, evrmore_address: str, display_name: Optional[str] = None) -> Dict[str, Any]:
        """Register a new user with a profile."""
        # Create or get the user
        user = User.get_by_address(evrmore_address)
        if not user:
            user = User.create(evrmore_address)
            logger.info(f"Created new user with address: {evrmore_address}")
        
        # Create a profile for the user if they don't have one
        profile = Profile.get_by_user_id(user.id)
        if not profile:
            profile = Profile(
                id=str(uuid.uuid4()),
                user_id=user.id,
                display_name=display_name or f"User_{user.id[:8]}"
            )
            profile.save()
            logger.info(f"Created new profile for user: {user.id}")
        
        return {
            "user_id": user.id,
            "evrmore_address": user.evrmore_address,
            "display_name": profile.display_name,
            "created_at": user.created_at
        }
    
    def update_profile(self, user_id: str, **profile_data) -> Profile:
        """Update a user's profile."""
        profile = Profile.get_by_user_id(user_id)
        
        if not profile:
            # Create profile if it doesn't exist
            profile = Profile(
                id=str(uuid.uuid4()),
                user_id=user_id
            )
        
        # Update profile fields
        for key, value in profile_data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        
        profile.updated_at = datetime.datetime.utcnow()
        profile.save()
        
        return profile
    
    def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a user's complete profile information."""
        user = User.get_by_id(user_id)
        if not user:
            return None
        
        profile = Profile.get_by_user_id(user_id)
        if not profile:
            # Create a default profile
            profile = Profile(
                id=str(uuid.uuid4()),
                user_id=user_id,
                display_name=f"User_{user_id[:8]}"
            )
            profile.save()
        
        # Get user settings
        settings = UserSetting.get_all_for_user(user_id)
        settings_dict = {s.setting_key: s.setting_value for s in settings}
        
        # Combine user, profile, and settings data
        return {
            "user_id": user.id,
            "evrmore_address": user.evrmore_address,
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "profile": {
                "display_name": profile.display_name,
                "bio": profile.bio,
                "avatar_url": profile.avatar_url,
                "created_at": profile.created_at,
                "updated_at": profile.updated_at
            },
            "settings": settings_dict
        }
    
    def set_user_setting(self, user_id: str, key: str, value: str) -> UserSetting:
        """Set a user setting."""
        setting = UserSetting.get_by_user_and_key(user_id, key)
        
        if not setting:
            # Create new setting
            setting = UserSetting(
                id=str(uuid.uuid4()),
                user_id=user_id,
                setting_key=key,
                setting_value=value
            )
        else:
            # Update existing setting
            setting.setting_value = value
            setting.updated_at = datetime.datetime.utcnow()
        
        setting.save()
        return setting
    
    def get_user_setting(self, user_id: str, key: str, default: str = None) -> Optional[str]:
        """Get a user setting value."""
        setting = UserSetting.get_by_user_and_key(user_id, key)
        if not setting:
            return default
        return setting.setting_value


# Demo function
def run_accounts_demo():
    """Run the accounts system demo."""
    logger.info("Initializing Evrmore Accounts System demo...")
    
    # Initialize the accounts system
    accounts = AccountSystem(debug=True)
    
    # Generate a test address and user
    address, wif_key = accounts.create_wallet_address()
    logger.info(f"Created test address: {address}")
    
    # Register the user
    user_data = accounts.register_user(address, "Test User")
    user_id = user_data["user_id"]
    logger.info(f"Registered user: {user_data}")
    
    # Generate authentication challenge
    challenge = accounts.generate_challenge(address)
    logger.info(f"Generated challenge: {challenge}")
    
    # Sign challenge
    signature = accounts.sign_message(wif_key, challenge)
    logger.info(f"Signed challenge")
    
    # Authenticate
    session = accounts.authenticate(address, challenge, signature)
    logger.info(f"Authenticated user: {session.user_id}")
    
    # Update profile
    profile = accounts.update_profile(
        user_id,
        display_name="Updated Name",
        bio="This is my bio",
        avatar_url="https://example.com/avatar.png"
    )
    logger.info(f"Updated profile: {profile.display_name}")
    
    # Set some user settings
    accounts.set_user_setting(user_id, "theme", "dark")
    accounts.set_user_setting(user_id, "language", "en")
    accounts.set_user_setting(user_id, "notifications", "true")
    
    # Get the complete user profile
    user_profile = accounts.get_user_profile(user_id)
    
    # Display the complete user data
    logger.info("\n=== USER PROFILE ===")
    logger.info(f"User ID: {user_profile['user_id']}")
    logger.info(f"Evrmore Address: {user_profile['evrmore_address']}")
    logger.info(f"Display Name: {user_profile['profile']['display_name']}")
    logger.info(f"Bio: {user_profile['profile']['bio']}")
    logger.info(f"Avatar URL: {user_profile['profile']['avatar_url']}")
    logger.info("\n=== USER SETTINGS ===")
    for key, value in user_profile['settings'].items():
        logger.info(f"{key}: {value}")
    
    logger.info("\nAccounts demo completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(run_accounts_demo()) 