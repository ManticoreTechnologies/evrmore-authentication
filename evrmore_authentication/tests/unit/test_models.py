#!/usr/bin/env python3
"""
Unit tests for the models module.
"""

import pytest
import os
import sys
import uuid
import datetime
from unittest.mock import patch, MagicMock

from evrmore_authentication.models import (
    User, Challenge, Session, OAuthClient, 
    OAuthAuthorizationCode, OAuthToken, SQLiteManager
)

@pytest.fixture
def db_manager():
    """Create a mocked SQLiteManager."""
    with patch('evrmore_authentication.models.SQLiteManager') as mock_db:
        # Mock fetchone and fetchall to return None by default
        mock_instance = MagicMock()
        mock_instance.fetchone.return_value = None
        mock_instance.fetchall.return_value = []
        
        # Make the class instantiation return our mock instance
        mock_db.return_value = mock_instance
        
        yield mock_instance

class TestUser:
    """Tests for the User model."""
    
    def test_user_creation(self):
        """Test creating a new User object."""
        test_id = str(uuid.uuid4())
        test_address = "EXAMPLEaddress123"
        
        user = User(
            id=test_id,
            evrmore_address=test_address,
            username="test_user",
            email="test@example.com",
            is_active=True
        )
        
        assert user.id == test_id
        assert user.evrmore_address == test_address
        assert user.username == "test_user"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert isinstance(user.created_at, datetime.datetime)
        assert user.last_login is None
    
    def test_user_to_dict(self):
        """Test converting a User to a dictionary."""
        test_id = str(uuid.uuid4())
        test_address = "EXAMPLEaddress123"
        test_date = datetime.datetime(2023, 1, 1, 12, 0, 0)
        
        user = User(
            id=test_id,
            evrmore_address=test_address,
            username="test_user",
            email="test@example.com",
            is_active=True,
            created_at=test_date
        )
        
        user_dict = user.to_dict()
        
        assert user_dict["id"] == test_id
        assert user_dict["evrmore_address"] == test_address
        assert user_dict["username"] == "test_user"
        assert user_dict["email"] == "test@example.com"
        assert user_dict["is_active"] is True
        assert user_dict["created_at"] == test_date.isoformat()
        assert user_dict["last_login"] is None
    
    def test_user_from_dict(self):
        """Test creating a User from a dictionary."""
        test_id = str(uuid.uuid4())
        test_address = "EXAMPLEaddress123"
        test_date = datetime.datetime(2023, 1, 1, 12, 0, 0)
        
        user_dict = {
            "id": test_id,
            "evrmore_address": test_address,
            "username": "test_user",
            "email": "test@example.com",
            "is_active": True,
            "created_at": test_date.isoformat(),
            "last_login": None
        }
        
        user = User.from_dict(user_dict)
        
        assert user.id == test_id
        assert user.evrmore_address == test_address
        assert user.username == "test_user"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.created_at.isoformat() == test_date.isoformat()
        assert user.last_login is None
    
    @patch('evrmore_authentication.models.SQLiteManager')
    def test_user_save(self, mock_db_class):
        """Test saving a User to the database."""
        # Setup mock
        mock_db = MagicMock()
        mock_db_class.return_value = mock_db
        
        test_id = str(uuid.uuid4())
        test_address = "EXAMPLEaddress123"
        
        user = User(
            id=test_id,
            evrmore_address=test_address,
            username="test_user",
            email="test@example.com"
        )
        
        # Mock fetchone to simulate user doesn't exist yet
        mock_db.fetchone.return_value = None
        
        user.save()
        
        # Verify execute was called with insert query
        mock_db.execute.assert_called_once()
        args, _ = mock_db.execute.call_args
        assert "INSERT INTO users" in args[0]
    
    @patch('evrmore_authentication.models.SQLiteManager')
    def test_user_get_by_id(self, mock_db_class):
        """Test getting a User by ID."""
        # Setup mock
        mock_db = MagicMock()
        mock_db_class.return_value = mock_db
        
        test_id = str(uuid.uuid4())
        test_address = "EXAMPLEaddress123"
        
        # Create a mock row result
        mock_row = {
            "id": test_id,
            "evrmore_address": test_address,
            "username": "test_user",
            "email": "test@example.com",
            "is_active": 1,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "last_login": None
        }
        
        # Mock the row to have dict-like behavior
        mock_row_obj = MagicMock()
        mock_row_obj.__getitem__ = lambda s, k: mock_row[k]
        mock_row_obj.keys = lambda: mock_row.keys()
        
        mock_db.fetchone.return_value = mock_row_obj
        
        user = User.get_by_id(test_id)
        
        assert user.id == test_id
        assert user.evrmore_address == test_address
        
        # Verify fetchone was called with the right query
        mock_db.fetchone.assert_called_once()
        args, _ = mock_db.fetchone.call_args
        assert "SELECT * FROM users WHERE id = ?" in args[0]
        assert args[1] == (test_id,)


class TestChallenge:
    """Tests for the Challenge model."""
    
    def test_challenge_creation(self):
        """Test creating a new Challenge object."""
        test_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        test_text = "test_challenge_text"
        test_expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        
        challenge = Challenge(
            id=test_id,
            user_id=test_user_id,
            challenge_text=test_text,
            expires_at=test_expires,
            used=False
        )
        
        assert challenge.id == test_id
        assert challenge.user_id == test_user_id
        assert challenge.challenge_text == test_text
        assert challenge.expires_at == test_expires
        assert challenge.used is False
        assert isinstance(challenge.created_at, datetime.datetime)
    
    def test_challenge_is_expired(self):
        """Test the is_expired property."""
        test_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        
        # Create an expired challenge
        expired_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        expired_challenge = Challenge(
            id=test_id,
            user_id=test_user_id,
            challenge_text="expired_challenge",
            expires_at=expired_time
        )
        
        # Create a valid challenge
        valid_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        valid_challenge = Challenge(
            id=str(uuid.uuid4()),
            user_id=test_user_id,
            challenge_text="valid_challenge",
            expires_at=valid_time
        )
        
        assert expired_challenge.is_expired is True
        assert valid_challenge.is_expired is False
    
    def test_challenge_to_dict(self):
        """Test converting a Challenge to a dictionary."""
        test_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        test_text = "test_challenge_text"
        test_expires = datetime.datetime(2023, 1, 1, 12, 15, 0)
        test_created = datetime.datetime(2023, 1, 1, 12, 0, 0)
        
        challenge = Challenge(
            id=test_id,
            user_id=test_user_id,
            challenge_text=test_text,
            expires_at=test_expires,
            used=False,
            created_at=test_created
        )
        
        challenge_dict = challenge.to_dict()
        
        assert challenge_dict["id"] == test_id
        assert challenge_dict["user_id"] == test_user_id
        assert challenge_dict["challenge_text"] == test_text
        assert challenge_dict["expires_at"] == test_expires.isoformat()
        assert challenge_dict["created_at"] == test_created.isoformat()
        assert challenge_dict["used"] is False


class TestSession:
    """Tests for the Session model."""
    
    def test_session_creation(self):
        """Test creating a new Session object."""
        test_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        test_token = "test_jwt_token"
        test_expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        session = Session(
            id=test_id,
            user_id=test_user_id,
            token=test_token,
            expires_at=test_expires,
            is_active=True,
            ip_address="127.0.0.1",
            user_agent="Test User Agent"
        )
        
        assert session.id == test_id
        assert session.user_id == test_user_id
        assert session.token == test_token
        assert session.expires_at == test_expires
        assert session.is_active is True
        assert session.ip_address == "127.0.0.1"
        assert session.user_agent == "Test User Agent"
        assert isinstance(session.created_at, datetime.datetime)
    
    def test_session_is_expired(self):
        """Test the is_expired property."""
        test_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        
        # Create an expired session
        expired_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        expired_session = Session(
            id=test_id,
            user_id=test_user_id,
            token="expired_token",
            expires_at=expired_time
        )
        
        # Create a valid session
        valid_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        valid_session = Session(
            id=str(uuid.uuid4()),
            user_id=test_user_id,
            token="valid_token",
            expires_at=valid_time
        )
        
        assert expired_session.is_expired is True
        assert valid_session.is_expired is False


class TestOAuthClient:
    """Tests for the OAuthClient model."""
    
    def test_oauth_client_creation(self):
        """Test creating a new OAuthClient object."""
        test_id = str(uuid.uuid4())
        test_client_id = str(uuid.uuid4())
        test_name = "Test OAuth Client"
        
        client = OAuthClient(
            id=test_id,
            client_id=test_client_id,
            client_secret="test_secret",
            client_name=test_name,
            redirect_uris=["https://example.com/callback"],
            allowed_response_types=["code"],
            allowed_scopes=["profile", "email"]
        )
        
        assert client.id == test_id
        assert client.client_id == test_client_id
        assert client.client_name == test_name
        assert "https://example.com/callback" in client.redirect_uris
        assert "code" in client.allowed_response_types
        assert "profile" in client.allowed_scopes
        assert "email" in client.allowed_scopes
    
    def test_verify_client_secret(self):
        """Test verifying a client secret."""
        client = OAuthClient(
            client_name="Test Client",
            client_secret="correct_secret"
        )
        
        assert client.verify_client_secret("correct_secret") is True
        assert client.verify_client_secret("wrong_secret") is False
    
    def test_verify_redirect_uri(self):
        """Test verifying a redirect URI."""
        client = OAuthClient(
            client_name="Test Client",
            redirect_uris=["https://example.com/callback", "https://app.example.com/oauth"]
        )
        
        assert client.verify_redirect_uri("https://example.com/callback") is True
        assert client.verify_redirect_uri("https://app.example.com/oauth") is True
        assert client.verify_redirect_uri("https://malicious.example.com/callback") is False
    
    def test_verify_scope(self):
        """Test verifying scopes."""
        client = OAuthClient(
            client_name="Test Client",
            allowed_scopes=["profile", "email", "read"]
        )
        
        assert client.verify_scope("profile") is True
        assert client.verify_scope("profile email") is True
        assert client.verify_scope("profile write") is False


class TestOAuthAuthorizationCode:
    """Tests for the OAuthAuthorizationCode model."""
    
    def test_authorization_code_creation(self):
        """Test creating a new OAuthAuthorizationCode object."""
        test_id = str(uuid.uuid4())
        test_code = "test_auth_code"
        test_client_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        test_redirect_uri = "https://example.com/callback"
        test_scope = "profile email"
        test_expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        
        auth_code = OAuthAuthorizationCode(
            id=test_id,
            code=test_code,
            client_id=test_client_id,
            user_id=test_user_id,
            redirect_uri=test_redirect_uri,
            scope=test_scope,
            expires_at=test_expires
        )
        
        assert auth_code.id == test_id
        assert auth_code.code == test_code
        assert auth_code.client_id == test_client_id
        assert auth_code.user_id == test_user_id
        assert auth_code.redirect_uri == test_redirect_uri
        assert auth_code.scope == test_scope
        assert auth_code.expires_at == test_expires
        assert auth_code.is_used is False
    
    def test_is_expired(self):
        """Test checking if the authorization code is expired."""
        # Create an expired code
        expired_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        expired_code = OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code="expired_code",
            client_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            redirect_uri="https://example.com/callback",
            scope="profile",
            expires_at=expired_time
        )
        
        # Create a valid code
        valid_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        valid_code = OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code="valid_code",
            client_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            redirect_uri="https://example.com/callback",
            scope="profile",
            expires_at=valid_time
        )
        
        assert expired_code.is_expired() is True
        assert valid_code.is_expired() is False
    
    def test_is_valid(self):
        """Test checking if the authorization code is valid for a client and redirect URI."""
        test_client_id = str(uuid.uuid4())
        test_redirect_uri = "https://example.com/callback"
        valid_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        
        # Create a valid code
        valid_code = OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code="valid_code",
            client_id=test_client_id,
            user_id=str(uuid.uuid4()),
            redirect_uri=test_redirect_uri,
            scope="profile",
            expires_at=valid_time
        )
        
        # Create an expired code
        expired_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        expired_code = OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code="expired_code",
            client_id=test_client_id,
            user_id=str(uuid.uuid4()),
            redirect_uri=test_redirect_uri,
            scope="profile",
            expires_at=expired_time
        )
        
        # Create a used code
        used_code = OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code="used_code",
            client_id=test_client_id,
            user_id=str(uuid.uuid4()),
            redirect_uri=test_redirect_uri,
            scope="profile",
            expires_at=valid_time,
            is_used=True
        )
        
        # Valid code with correct client_id and redirect_uri
        assert valid_code.is_valid(test_client_id, test_redirect_uri) is True
        
        # Valid code with incorrect client_id
        assert valid_code.is_valid("wrong_client_id", test_redirect_uri) is False
        
        # Valid code with incorrect redirect_uri
        assert valid_code.is_valid(test_client_id, "https://wrong.example.com/callback") is False
        
        # Expired code
        assert expired_code.is_valid(test_client_id, test_redirect_uri) is False
        
        # Used code
        assert used_code.is_valid(test_client_id, test_redirect_uri) is False


class TestOAuthToken:
    """Tests for the OAuthToken model."""
    
    def test_oauth_token_creation(self):
        """Test creating a new OAuthToken object."""
        test_id = str(uuid.uuid4())
        test_access_token = "test_access_token"
        test_refresh_token = "test_refresh_token"
        test_client_id = str(uuid.uuid4())
        test_user_id = str(uuid.uuid4())
        test_scope = "profile email"
        test_access_expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        test_refresh_expires = datetime.datetime.utcnow() + datetime.timedelta(days=7)
        
        token = OAuthToken(
            id=test_id,
            access_token=test_access_token,
            refresh_token=test_refresh_token,
            client_id=test_client_id,
            user_id=test_user_id,
            scope=test_scope,
            access_token_expires_at=test_access_expires,
            refresh_token_expires_at=test_refresh_expires
        )
        
        assert token.id == test_id
        assert token.access_token == test_access_token
        assert token.refresh_token == test_refresh_token
        assert token.client_id == test_client_id
        assert token.user_id == test_user_id
        assert token.scope == test_scope
        assert token.access_token_expires_at == test_access_expires
        assert token.refresh_token_expires_at == test_refresh_expires
        assert token.is_active is True
        assert token.revoked_at is None
    
    def test_token_expiration(self):
        """Test checking if tokens are expired."""
        now = datetime.datetime.utcnow()
        
        # Create a token with expired access token but valid refresh token
        expired_access = OAuthToken(
            id=str(uuid.uuid4()),
            access_token="expired_access",
            refresh_token="valid_refresh",
            client_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            scope="profile",
            access_token_expires_at=now - datetime.timedelta(minutes=5),
            refresh_token_expires_at=now + datetime.timedelta(days=7)
        )
        
        # Create a token with expired refresh token but valid access token
        expired_refresh = OAuthToken(
            id=str(uuid.uuid4()),
            access_token="valid_access",
            refresh_token="expired_refresh",
            client_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            scope="profile",
            access_token_expires_at=now + datetime.timedelta(hours=1),
            refresh_token_expires_at=now - datetime.timedelta(days=1)
        )
        
        # Create a valid token
        valid_token = OAuthToken(
            id=str(uuid.uuid4()),
            access_token="valid_access",
            refresh_token="valid_refresh",
            client_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            scope="profile",
            access_token_expires_at=now + datetime.timedelta(hours=1),
            refresh_token_expires_at=now + datetime.timedelta(days=7)
        )
        
        assert expired_access.is_access_token_expired() is True
        assert expired_access.is_refresh_token_expired() is False
        
        assert expired_refresh.is_access_token_expired() is False
        assert expired_refresh.is_refresh_token_expired() is True
        
        assert valid_token.is_access_token_expired() is False
        assert valid_token.is_refresh_token_expired() is False
    
    def test_token_revocation(self):
        """Test revoking a token."""
        token = OAuthToken(
            id=str(uuid.uuid4()),
            access_token="test_access",
            refresh_token="test_refresh",
            client_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            scope="profile",
            access_token_expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            refresh_token_expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )
        
        # Mock the save method to avoid database interaction
        with patch.object(token, 'save', return_value=True):
            assert token.is_active is True
            assert token.revoked_at is None
            
            # Revoke the token
            result = token.revoke()
            
            assert result is True
            assert token.is_active is False
            assert token.revoked_at is not None
            
            # The save method should have been called
            token.save.assert_called_once()
    
    @patch('evrmore_authentication.models.SQLiteManager')
    def test_get_by_access_token(self, mock_db_class):
        """Test getting a token by access token."""
        # Setup mock
        mock_db = MagicMock()
        mock_db_class.return_value = mock_db
        
        test_id = str(uuid.uuid4())
        test_access_token = "test_access_token"
        now = datetime.datetime.utcnow()
        
        # Create a mock row result
        mock_row = {
            "id": test_id,
            "access_token": test_access_token,
            "refresh_token": "test_refresh_token",
            "client_id": str(uuid.uuid4()),
            "user_id": str(uuid.uuid4()),
            "scope": "profile",
            "access_token_expires_at": (now + datetime.timedelta(hours=1)).isoformat(),
            "refresh_token_expires_at": (now + datetime.timedelta(days=7)).isoformat(),
            "created_at": now.isoformat(),
            "is_active": 1,
            "revoked_at": None
        }
        
        # Mock the row to have dict-like behavior
        mock_row_obj = MagicMock()
        mock_row_obj.__getitem__ = lambda s, k: mock_row[k]
        mock_row_obj.keys = lambda: mock_row.keys()
        
        mock_db.fetchone.return_value = mock_row_obj
        
        # Call the method
        with patch('evrmore_authentication.models.OAuthToken._from_row', return_value=MagicMock()) as mock_from_row:
            OAuthToken.get_by_access_token(test_access_token)
            
            # Verify fetchone was called with the right query
            mock_db.fetchone.assert_called_once()
            args, _ = mock_db.fetchone.call_args
            assert "SELECT * FROM oauth_tokens WHERE access_token = ?" in args[0]
            assert args[1] == (test_access_token,)
            
            # Verify _from_row was called with the mock row
            mock_from_row.assert_called_once_with(mock_row_obj) 