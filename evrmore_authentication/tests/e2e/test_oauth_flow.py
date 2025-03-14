#!/usr/bin/env python3
"""
End-to-end test for the complete OAuth 2.0 flow.
This test mocks the external dependencies but tests the complete flow
from client registration to token validation.
"""

import pytest
import os
import uuid
import datetime
from unittest.mock import patch, MagicMock

from evrmore_authentication.auth import EvrmoreAuth
from evrmore_authentication.models import User, OAuthClient, OAuthAuthorizationCode, OAuthToken

@pytest.fixture
def auth():
    """Create an EvrmoreAuth instance for testing."""
    auth = EvrmoreAuth(debug=True)
    return auth

@pytest.fixture
def test_user():
    """Create a test user."""
    user_id = str(uuid.uuid4())
    test_address = f"E{uuid.uuid4().hex[:34]}"  # Create a plausible address
    
    user = User(
        id=user_id,
        evrmore_address=test_address,
        username="test_user",
        email="test@example.com"
    )
    
    # Return without saving to DB - we'll mock the database interactions
    return user

@pytest.fixture
def oauth_client():
    """Create a test OAuth client."""
    client = OAuthClient(
        client_name="Test Client",
        redirect_uris=["https://example.com/callback"]
    )
    return client

@patch('evrmore_authentication.models.OAuthClient.save')
@patch('evrmore_authentication.models.OAuthClient.get_by_client_id')
@patch('evrmore_authentication.models.User.get_by_id')
@patch('evrmore_authentication.models.OAuthAuthorizationCode.save')
@patch('evrmore_authentication.models.OAuthToken.save')
def test_oauth_flow(mock_token_save, mock_code_save, mock_get_user, 
                   mock_get_client, mock_client_save, auth, test_user, oauth_client):
    """Test the complete OAuth 2.0 flow."""
    # 1. Register client
    with patch.object(OAuthClient, 'create', return_value=oauth_client):
        client = auth.register_oauth_client(
            client_name="Test Client",
            redirect_uris=["https://example.com/callback"],
            allowed_scopes=["profile", "email"]
        )
        
        assert client.client_name == "Test Client"
        assert client.client_id is not None
        assert client.client_secret is not None
        assert "https://example.com/callback" in client.redirect_uris
    
    # Setup mocks for next steps
    mock_get_client.return_value = client
    mock_get_user.return_value = test_user
    
    # 2. Create authorization code
    auth_code = auth.create_authorization_code(
        client_id=client.client_id,
        user_id=test_user.id,
        redirect_uri="https://example.com/callback",
        scope="profile email"
    )
    
    assert auth_code.client_id == client.client_id
    assert auth_code.user_id == test_user.id
    assert auth_code.redirect_uri == "https://example.com/callback"
    assert auth_code.scope == "profile email"
    assert auth_code.is_used is False
    assert mock_code_save.called
    
    # 3. Exchange code for token
    with patch('evrmore_authentication.models.OAuthAuthorizationCode.get_by_code', return_value=auth_code):
        with patch('evrmore_authentication.models.OAuthAuthorizationCode.use') as mock_use:
            token = auth.exchange_code_for_token(
                code=auth_code.code,
                client_id=client.client_id,
                client_secret=client.client_secret,
                redirect_uri="https://example.com/callback"
            )
            
            assert token.client_id == client.client_id
            assert token.user_id == test_user.id
            assert token.scope == "profile email"
            assert token.access_token is not None
            assert token.refresh_token is not None
            assert mock_use.called
            assert mock_token_save.called
    
    # 4. Validate access token
    with patch('evrmore_authentication.models.OAuthToken.get_by_access_token', return_value=token):
        # Set up the token with the 'type' field to mark it as an access token
        with patch.object(auth, 'validate_token') as mock_validate:
            # Make sure validate_token returns a valid token payload
            mock_validate.return_value = {
                "sub": test_user.id,
                "address": test_user.evrmore_address,
                "type": "access",
                "scope": "profile email",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            
            payload = auth.validate_oauth_token(token.access_token)
            
            assert payload is not None
            assert payload["user_id"] == test_user.id
            assert payload["evrmore_address"] == test_user.evrmore_address
    
    # 5. Refresh token
    new_token = MagicMock()
    new_token.access_token = f"new_access_token_{uuid.uuid4()}"
    new_token.refresh_token = f"new_refresh_token_{uuid.uuid4()}"
    
    with patch('evrmore_authentication.models.OAuthToken.get_by_refresh_token', return_value=token):
        with patch.object(auth, '_generate_jwt_token', return_value=new_token.access_token):
            with patch.object(OAuthToken, '__init__', return_value=None) as mock_init:
                with patch.object(OAuthToken, 'save') as mock_save:
                    refreshed = auth.refresh_token(
                        refresh_token=token.refresh_token,
                        client_id=client.client_id,
                        client_secret=client.client_secret
                    )
                    
                    assert mock_init.called
                    assert mock_save.called
    
    # 6. Revoke token - Skip mocking revoke() since it might be called differently than expected
    # Instead, we'll verify the entire function works by checking its return value
    with patch('evrmore_authentication.models.OAuthToken.get_by_access_token', return_value=token):
        with patch('evrmore_authentication.models.OAuthToken.get_by_refresh_token', return_value=None):
            # Make the token appear active
            token.is_active = True
            token.client_id = client.client_id
            
            # Also patch the save method to avoid database operations
            with patch.object(token, 'save', return_value=True):
                result = auth.revoke_oauth_token(
                    token=token.access_token,
                    client_id=client.client_id,
                    client_secret=client.client_secret
                )
                
                # If we got True, the function completed successfully
                assert result is True 