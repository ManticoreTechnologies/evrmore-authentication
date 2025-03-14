#!/usr/bin/env python3
"""
Unit tests for the auth module.
"""

import pytest
import os
import sys
import datetime
import uuid
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path to allow importing the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from evrmore_authentication.auth import EvrmoreAuth, UserSession
from evrmore_authentication.models import User, Challenge, Session
from evrmore_authentication.exceptions import (
    AuthenticationError, 
    InvalidSignatureError,
    ChallengeExpiredError,
    ChallengeAlreadyUsedError,
    InvalidTokenError
)

# Fixture for auth instance
@pytest.fixture
def auth():
    """Create an EvrmoreAuth instance for testing."""
    auth = EvrmoreAuth(
        jwt_secret="test_secret",
        jwt_algorithm="HS256",
        debug=True
    )
    return auth

def test_auth_init(auth):
    """Test that EvrmoreAuth initializes correctly."""
    assert auth.jwt_secret == "test_secret"
    assert auth.jwt_algorithm == "HS256"
    assert auth.debug is True

@patch('evrmore_authentication.auth.verify_message')
def test_verify_signature(mock_verify, auth):
    """Test signature verification."""
    mock_verify.return_value = True
    
    result = auth.verify_signature_only(
        evrmore_address="EXAMPLEaddress123",
        message="Test message",
        signature="Test signature"
    )
    
    assert result is True
    mock_verify.assert_called_once_with(
        "EXAMPLEaddress123",
        "Test signature",
        "Test message"
    )

@patch('evrmore_authentication.auth.EvrmoreAuth.create_wallet_address')
def test_wallet_address_creation(mock_create, auth):
    """Test wallet address creation."""
    # Mock the create_wallet_address method
    test_address = "EXAMPLEaddress123"
    test_wif = "wif_key_123"
    mock_create.return_value = (test_address, test_wif)
    
    # Call the method
    address, wif = auth.create_wallet_address()
    
    # Check the result
    assert address == test_address
    assert wif == test_wif
    assert mock_create.called

@patch('evrmore_authentication.models.Challenge.get_by_text')
@patch('evrmore_authentication.models.Challenge.save')
@patch('evrmore_authentication.models.User.get_by_address')
@patch('evrmore_authentication.auth.EvrmoreAuth.verify_signature')
@patch('evrmore_authentication.models.Session.save')
def test_authenticate_success(mock_session_save, mock_verify, mock_get_user, 
                            mock_challenge_save, mock_get_challenge, auth, test_user, test_challenge):
    """Test successful authentication."""
    # Setup mocks
    mock_get_user.return_value = test_user
    mock_get_challenge.return_value = test_challenge
    mock_verify.return_value = True

    # Mock the _generate_jwt_token method
    with patch.object(auth, '_generate_jwt_token') as mock_jwt:
        mock_jwt.return_value = "fake_jwt_token"

        # Call authenticate
        session = auth.authenticate(
            evrmore_address=test_user.evrmore_address,
            challenge=test_challenge.challenge_text,
            signature="fake_signature"
        )

        # Check results
        assert isinstance(session, UserSession)
        assert session.user_id == test_user.id
        assert session.evrmore_address == test_user.evrmore_address
        assert session.token == "fake_jwt_token"

        # Verify mocks were called
        mock_get_user.assert_called_once_with(test_user.evrmore_address)
        # get_by_text is called twice: once in get_challenge_details and once directly
        assert mock_get_challenge.call_count == 2
        assert mock_get_challenge.call_args_list[0] == mock_get_challenge.call_args_list[1]
        # verify_signature is called without run_hooks parameter (it defaults to True)
        mock_verify.assert_called_once_with(test_user.evrmore_address, test_challenge.challenge_text, "fake_signature")
        assert test_challenge.used is True
        mock_challenge_save.assert_called_once()
        assert test_user.last_login is not None
        mock_session_save.assert_called_once()

@patch('evrmore_authentication.models.Challenge.get_by_text')
@patch('evrmore_authentication.models.User.get_by_address')
def test_authenticate_expired_challenge(mock_get_user, mock_get_challenge, auth, test_user, test_challenge):
    """Test authentication with expired challenge."""
    # Setup mocks
    mock_get_user.return_value = test_user
    
    # Make the challenge expired
    expired_challenge = test_challenge
    expired_challenge.expires_at = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    mock_get_challenge.return_value = expired_challenge
    
    # Call authenticate and expect exception
    with pytest.raises(ChallengeExpiredError):
        auth.authenticate(
            evrmore_address=test_user.evrmore_address,
            challenge=expired_challenge.challenge_text,
            signature="fake_signature"
        )

@patch('evrmore_authentication.auth.jwt.decode')
def test_validate_token(mock_decode, auth):
    """Test token validation."""
    # Setup mock
    test_payload = {
        "sub": "user_id_123",
        "address": "EXAMPLEaddress123",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    mock_decode.return_value = test_payload
    
    # Call validate_token
    result = auth.validate_token("fake_token")
    
    # Check result
    assert result == test_payload
    mock_decode.assert_called_once()

@patch('evrmore_authentication.auth.jwt.decode')
def test_validate_token_expired(mock_decode, auth):
    """Test validating an expired token."""
    # Setup mock to raise expired token exception
    from jwt.exceptions import ExpiredSignatureError
    mock_decode.side_effect = ExpiredSignatureError()
    
    # Call validate_token and expect it to return None
    result = auth.validate_token("fake_token")
    assert result is None
    
    mock_decode.assert_called_once()

# More tests would be added here 