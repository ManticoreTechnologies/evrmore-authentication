#!/usr/bin/env python3
"""
SQLite Backend Tests for Evrmore Authentication

This module tests the SQLite implementation of the Evrmore Authentication system.

© 2023-2024 Manticore Technologies - manticore.technology
"""

import os
import sys
import unittest
import tempfile
import datetime
import uuid
from pathlib import Path

# Add the parent directory to the path so we can import from the module
parent_dir = str(Path(__file__).parent.parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from evrmore_authentication.models import User, Challenge, Session, SQLiteManager

class TestSQLiteModels(unittest.TestCase):
    """Test the SQLite models."""
    
    def setUp(self):
        """Set up a temporary database for tests."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        os.environ['SQLITE_DB_PATH'] = self.temp_db.name
        
        # Ensure we re-initialize the singleton
        SQLiteManager._instance = None
        self.db = SQLiteManager()
    
    def tearDown(self):
        """Clean up the temporary database."""
        os.environ.pop('SQLITE_DB_PATH', None)
        try:
            os.unlink(self.temp_db.name)
        except:
            pass
    
    def test_user_crud(self):
        """Test user create, read, update, delete operations."""
        user_id = str(uuid.uuid4())
        address = f"E{uuid.uuid4().hex[:34]}"
        
        # Create
        user = User(
            id=user_id,
            evrmore_address=address,
            username="test_user",
            email="test@example.com"
        )
        user.save()
        
        # Read
        retrieved = User.get_by_id(user_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, user_id)
        self.assertEqual(retrieved.evrmore_address, address)
        self.assertEqual(retrieved.username, "test_user")
        
        # Update
        retrieved.email = "updated@example.com"
        retrieved.save()
        
        # Verify update
        updated = User.get_by_id(user_id)
        self.assertEqual(updated.email, "updated@example.com")
        
        # Get by address
        by_address = User.get_by_address(address)
        self.assertIsNotNone(by_address)
        self.assertEqual(by_address.id, user_id)
    
    def test_challenge_crud(self):
        """Test challenge create, read, update, delete operations."""
        user_id = str(uuid.uuid4())
        challenge_id = str(uuid.uuid4())
        challenge_text = f"test_challenge_{uuid.uuid4().hex}"
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        
        # Create a user first
        user = User(
            id=user_id,
            evrmore_address=f"E{uuid.uuid4().hex[:34]}"
        )
        user.save()
        
        # Create challenge
        challenge = Challenge(
            id=challenge_id,
            user_id=user_id,
            challenge_text=challenge_text,
            expires_at=expires_at
        )
        challenge.save()
        
        # Read
        retrieved = Challenge.get_by_id(challenge_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, challenge_id)
        self.assertEqual(retrieved.user_id, user_id)
        self.assertEqual(retrieved.challenge_text, challenge_text)
        
        # Update
        retrieved.used = True
        retrieved.save()
        
        # Verify update
        updated = Challenge.get_by_id(challenge_id)
        self.assertTrue(updated.used)
        
        # Get by text
        by_text = Challenge.get_by_text(challenge_text)
        self.assertIsNotNone(by_text)
        self.assertEqual(by_text.id, challenge_id)
        
        # Get by user ID
        by_user = Challenge.get_by_user_id(user_id)
        self.assertEqual(len(by_user), 1)
        self.assertEqual(by_user[0].id, challenge_id)
    
    def test_session_crud(self):
        """Test session create, read, update, delete operations."""
        user_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        token = f"token_{uuid.uuid4().hex}"
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        # Create a user first
        user = User(
            id=user_id,
            evrmore_address=f"E{uuid.uuid4().hex[:34]}"
        )
        user.save()
        
        # Create session
        session = Session(
            id=session_id,
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address="127.0.0.1",
            user_agent="test-agent"
        )
        session.save()
        
        # Read
        retrieved = Session.get_by_id(session_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, session_id)
        self.assertEqual(retrieved.user_id, user_id)
        self.assertEqual(retrieved.token, token)
        
        # Update
        retrieved.is_active = False
        retrieved.save()
        
        # Verify update
        updated = Session.get_by_id(session_id)
        self.assertFalse(updated.is_active)
        
        # Get by token
        by_token = Session.get_by_token(token)
        self.assertIsNotNone(by_token)
        self.assertEqual(by_token.id, session_id)
        
        # Get by user ID
        by_user = Session.get_by_user_id(user_id)
        self.assertEqual(len(by_user), 1)
        self.assertEqual(by_user[0].id, session_id)

if __name__ == "__main__":
    unittest.main() 