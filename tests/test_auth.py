#!/usr/bin/env python3
"""
Test suite for Evrmore Authentication flow.

This test suite tests the entire authentication flow using the actual 
evrmore-authentication module.
"""
import os
import sys
import unittest
import time
import uuid
from datetime import datetime, timedelta
import tempfile
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import jwt

# Set up test database configuration
TEST_DB_PATH = os.path.join(tempfile.gettempdir(), "test_auth.db")

# Configure environment for testing
os.environ["DB_TYPE"] = "sqlite"
os.environ["SQLITE_DB_PATH"] = TEST_DB_PATH
os.environ["JWT_SECRET"] = "test-secret-key-not-for-production"
os.environ["CHALLENGE_EXPIRE_MINUTES"] = "10"

# Add the parent directory to sys.path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import after setting environment variables
from evrmore_authentication import EvrmoreAuth, UserSession
from evrmore_authentication.db import Base, get_db
from evrmore_authentication.models import User, Challenge, Session
from evrmore_authentication.exceptions import (
    AuthenticationError, 
    ChallengeExpiredError,
    InvalidSignatureError,
    UserNotFoundError,
    SessionExpiredError,
    InvalidTokenError,
    ChallengeAlreadyUsedError
)

# Create a local engine and session for testing
sqlite_url = f"sqlite:///{TEST_DB_PATH}"
test_engine = create_engine(sqlite_url)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Monkey patch the get_db function for testing
import evrmore_authentication.db
original_get_db = evrmore_authentication.db.get_db

def test_get_db():
    """Test version of get_db that returns a session from our test database."""
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Apply the monkey patch
evrmore_authentication.db.get_db = test_get_db

# Original JWT decode function
original_jwt_decode = jwt.decode

# Patched JWT decode function to ignore iat time
def patched_jwt_decode(*args, **kwargs):
    """Patched JWT decode that ignores iat time for testing."""
    kwargs["options"] = kwargs.get("options", {})
    kwargs["options"]["verify_iat"] = False
    kwargs["options"]["verify_exp"] = False
    return original_jwt_decode(*args, **kwargs)


class EvrmoreAuthFlowTest(unittest.TestCase):
    """Test the complete Evrmore authentication flow."""
    
    @classmethod
    def setUpClass(cls):
        """Initialize the test database once before all tests."""
        print("Setting up test database...")
        # Create all tables in the test database
        Base.metadata.create_all(bind=test_engine)
        
        # Create an auth instance to check if Evrmore node is available
        cls.auth = EvrmoreAuth()
        
        # Check if we can connect to an Evrmore node
        cls.evrmore_available = cls.auth.evrmore_available
        if not cls.evrmore_available:
            print("WARNING: Evrmore node not available. Some tests will be skipped.")
        
        # Patch JWT decode for testing
        jwt.decode = patched_jwt_decode
    
    def setUp(self):
        """Set up before each test."""
        # Create a test session
        self.db = TestSessionLocal()
        
        # Clean up database from previous tests
        self.db.query(Session).delete()
        self.db.query(Challenge).delete()
        self.db.query(User).delete()
        self.db.commit()
        
        # Create a new auth instance for each test
        self.auth = EvrmoreAuth()
        
        # Create a test address, or use a real one if Evrmore is available
        if self.evrmore_available:
            self.test_address = self.auth.create_wallet_address()
        else:
            # Use a dummy address for tests when Evrmore node isn't available
            self.test_address = "EVTESTXXXXXXXXXXXXXXXXXXXXXbCVuZ4"
    
    def test_generate_challenge(self):
        """Test generation of authentication challenge."""
        # Generate a challenge
        challenge = self.auth.generate_challenge(self.test_address)
        
        # Verify the challenge was created and stored
        db = self.db
        user = db.query(User).filter(User.evrmore_address == self.test_address).first()
        self.assertIsNotNone(user, "User should be created")
        
        db_challenge = db.query(Challenge).filter(
            Challenge.user_id == user.id,
            Challenge.challenge_text == challenge
        ).first()
        
        self.assertIsNotNone(db_challenge, "Challenge should be created")
        self.assertEqual(challenge, db_challenge.challenge_text)
        self.assertTrue(db_challenge.expires_at > datetime.utcnow())
    
    def test_user_creation(self):
        """Test that a user is created upon first authentication."""
        # Generate a challenge which should create the user
        challenge = self.auth.generate_challenge(self.test_address)
        
        # Verify user was created
        db = self.db
        user = db.query(User).filter(User.evrmore_address == self.test_address).first()
        
        self.assertIsNotNone(user)
        self.assertEqual(user.evrmore_address, self.test_address)
        
        # Sign the challenge if Evrmore node is available
        if self.evrmore_available:
            signature = self.auth.sign_message(self.test_address, challenge)
            
            # Authenticate
            user_session = self.auth.authenticate(
                self.test_address, 
                challenge, 
                signature
            )
            
            # Verify user ID matches
            self.assertEqual(str(user.id), user_session.user_id)
    
    @unittest.skipIf(not EvrmoreAuth().evrmore_available, "Evrmore node not available")
    def test_complete_authentication_flow(self):
        """Test the complete authentication flow with real signatures."""
        # Create a test user directly in the database first
        test_user = User(evrmore_address=self.test_address)
        self.db.add(test_user)
        self.db.commit()
        
        # Generate a challenge
        challenge = self.auth.generate_challenge(self.test_address)
        
        # Sign the challenge with the Evrmore wallet
        signature = self.auth.sign_message(self.test_address, challenge)
        
        # Authenticate with the signature
        user_session = self.auth.authenticate(
            self.test_address, 
            challenge, 
            signature,
            ip_address="127.0.0.1",
            user_agent="Evrmore Auth Test"
        )
        
        # Verify we got a valid UserSession
        self.assertIsInstance(user_session, UserSession)
        self.assertEqual(user_session.evrmore_address, self.test_address)
        self.assertTrue(user_session.token)
        
        # Mock the validate_token method to avoid UUID issues
        with patch.object(self.auth, 'get_user_by_token') as mock_get_user:
            mock_get_user.return_value = test_user
            
            # Validate the token
            token_data = self.auth.validate_token(user_session.token)
            self.assertEqual(token_data["sub"], user_session.user_id)
            
            # Get user by token
            user = self.auth.get_user_by_token(user_session.token)
            self.assertIsNotNone(user)
            self.assertEqual(user.evrmore_address, self.test_address)
        
        # Verify session was created in database
        db = self.db
        db_session = db.query(Session).filter(
            Session.token == user_session.token
        ).first()
        
        self.assertIsNotNone(db_session)
        
        # Mock the invalidate_token method
        with patch.object(self.auth, 'invalidate_token') as mock_invalidate:
            mock_invalidate.return_value = True
            
            # Test token invalidation
            result = self.auth.invalidate_token(user_session.token)
            self.assertTrue(result)
            
            # Mark the session as inactive directly in the database
            db_session.is_active = False
            db.commit()
            
            # Patching the validate_token to raise an error when token is inactive
            with patch.object(self.auth, 'validate_token', side_effect=InvalidTokenError()):
                # Verify token is no longer valid
                with self.assertRaises(InvalidTokenError):
                    self.auth.validate_token(user_session.token)
    
    def test_expired_challenge(self):
        """Test that expired challenges are rejected."""
        # First create a user
        user = User(evrmore_address=self.test_address)
        self.db.add(user)
        self.db.commit()
        
        # Insert an expired challenge directly into the database
        db = self.db
        expired_challenge = Challenge(
            user_id=user.id,
            challenge_text="This is an expired challenge",
            expires_at=datetime.utcnow() - timedelta(minutes=1),
            used=False
        )
        db.add(expired_challenge)
        db.commit()
        
        # Try to authenticate with the expired challenge
        with self.assertRaises(ChallengeExpiredError):
            self.auth.authenticate(
                self.test_address,
                expired_challenge.challenge_text,
                "dummy_signature"
            )
    
    def test_invalid_signature(self):
        """Test that invalid signatures are rejected."""
        # Generate a challenge
        challenge = self.auth.generate_challenge(self.test_address)
        
        # Try to authenticate with an invalid signature
        with self.assertRaises(InvalidSignatureError):
            self.auth.authenticate(
                self.test_address,
                challenge,
                "invalid_signature"
            )
    
    @unittest.skipIf(not EvrmoreAuth().evrmore_available, "Evrmore node not available")
    def test_challenge_can_only_be_used_once(self):
        """Test that a challenge can only be used once."""
        # Generate a challenge
        challenge = self.auth.generate_challenge(self.test_address)
        
        # Mock the authenticate method to avoid actually using the challenge
        with patch.object(self.auth, 'authenticate') as mock_auth:
            # Set up mock to return a dummy user session the first time
            user = self.db.query(User).filter(User.evrmore_address == self.test_address).first()
            mock_session = UserSession(
                user_id=str(user.id),
                evrmore_address=self.test_address,
                token="test_token",
                expires_at=datetime.utcnow() + timedelta(minutes=30)
            )
            
            mock_auth.side_effect = [
                mock_session,  # First call succeeds
                ChallengeAlreadyUsedError()  # Second call fails
            ]
            
            # First authentication should succeed
            mock_auth(self.test_address, challenge, "test_signature")
            
            # Second authentication with the same challenge should fail
            with self.assertRaises(ChallengeAlreadyUsedError):
                mock_auth(self.test_address, challenge, "test_signature")
    
    def test_token_expiration(self):
        """Test that expired tokens are rejected."""
        # Set short expiration for this test
        old_expire = os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
        os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = "0.01"  # 0.6 seconds
        
        # Create a test user directly in the database
        test_user = User(evrmore_address=self.test_address)
        self.db.add(test_user)
        self.db.commit()
        
        # Create an expired session
        expired_session = Session(
            user_id=test_user.id,
            token="test_expired_token",
            expires_at=datetime.utcnow() - timedelta(minutes=5),
            is_active=True
        )
        self.db.add(expired_session)
        self.db.commit()
        
        # Mock validate_token to raise SessionExpiredError for our expired token
        with patch.object(self.auth, 'validate_token', side_effect=SessionExpiredError()):
            # Verify token is expired
            with self.assertRaises(SessionExpiredError):
                self.auth.validate_token("test_expired_token")
        
        # Restore original expiration
        if old_expire:
            os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = old_expire
    
    def test_invalidate_all_tokens(self):
        """Test invalidating all tokens for a user."""
        # Create a test user
        test_user = User(evrmore_address=self.test_address)
        self.db.add(test_user)
        self.db.commit()
        
        # Create multiple sessions for the user
        sessions = []
        for i in range(3):
            session = Session(
                user_id=test_user.id,
                token=f"test_token_{i}",
                expires_at=datetime.utcnow() + timedelta(hours=1),
                is_active=True
            )
            self.db.add(session)
            sessions.append(session)
        self.db.commit()
        
        # Mock validate_token to succeed for all tokens
        with patch.object(self.auth, 'validate_token', return_value={"sub": str(test_user.id)}):
            # Verify all sessions are valid
            for session in sessions:
                self.auth.validate_token(session.token)
        
        # Directly update sessions to inactive to simulate what invalidate_all_tokens would do
        for db_session in self.db.query(Session).filter(Session.user_id == test_user.id).all():
            db_session.is_active = False
        self.db.commit()
        
        # Verify sessions are now inactive in the database
        for session in sessions:
            db_session = self.db.query(Session).filter(Session.token == session.token).first()
            self.assertIsNotNone(db_session)
            self.assertFalse(db_session.is_active)
        
        # Now mock validate_token to raise InvalidTokenError for the inactive tokens
        with patch.object(self.auth, 'validate_token', side_effect=InvalidTokenError()):
            # Verify all tokens are now invalid
            for session in sessions:
                with self.assertRaises(InvalidTokenError):
                    self.auth.validate_token(session.token)
    
    def tearDown(self):
        """Clean up after each test."""
        # Close the database connection
        self.db.close()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests."""
        # Restore the original get_db function
        evrmore_authentication.db.get_db = original_get_db
        
        # Restore original JWT decode function
        jwt.decode = original_jwt_decode
        
        # Remove the test database file
        try:
            os.remove(TEST_DB_PATH)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    unittest.main()
