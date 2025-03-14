#!/usr/bin/env python3
"""
Integration tests for the API endpoints.
"""

import pytest
import os
import sys
import json
import requests
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path to allow importing the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from evrmore_authentication.api import app
from evrmore_authentication.auth import EvrmoreAuth
from fastapi.testclient import TestClient

# Create test client
client = TestClient(app)

@pytest.fixture
def mock_auth():
    """Mock EvrmoreAuth for API testing."""
    with patch('evrmore_authentication.api.auth') as mock_auth:
        mock_auth.debug = True
        mock_auth.generate_challenge.return_value = "test_challenge"
        mock_auth.authenticate.return_value = MagicMock(
            user_id="test_user_id",
            evrmore_address="test_address",
            token="test_token"
        )
        mock_auth.validate_token.return_value = {
            "sub": "test_user_id",
            "address": "test_address",
            "exp": "2099-01-01T00:00:00"
        }
        yield mock_auth

def test_validate_token_endpoint(mock_auth):
    """Test the token validation endpoint."""
    response = client.get("/validate?token=test_token")
    
    # Check the response
    assert response.status_code == 200
    assert "valid" in response.json()
    
    # Verify that the auth service was called correctly
    mock_auth.validate_token.assert_called_once_with("test_token")

def test_get_challenge(mock_auth):
    """Test the /challenge endpoint."""
    response = client.post(
        "/challenge",
        json={"evrmore_address": "EXAMPLEaddress123", "expire_minutes": 10}
    )
    
    assert response.status_code == 200
    assert "challenge" in response.json()
    
    # Verify that generate_challenge was called
    mock_auth.generate_challenge.assert_called_once_with("EXAMPLEaddress123", expire_minutes=10)

def test_verify_signature(mock_auth):
    """Test the /authenticate endpoint."""
    response = client.post(
        "/authenticate",
        json={
            "evrmore_address": "EXAMPLEaddress123",
            "challenge": "test_challenge",
            "signature": "test_signature"
        }
    )
    
    assert response.status_code == 200
    assert "token" in response.json()
    
    # Verify that authenticate was called
    mock_auth.authenticate.assert_called_once_with(
        evrmore_address="EXAMPLEaddress123",
        challenge="test_challenge",
        signature="test_signature",
        ip_address=None,
        user_agent="testclient",
        token_expire_minutes=None
    )

# More tests would be added here 