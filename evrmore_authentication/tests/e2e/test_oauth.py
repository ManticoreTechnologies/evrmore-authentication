#!/usr/bin/env python3
"""
End-to-end tests for the OAuth 2.0 authentication flow.
"""

import pytest
import os
import sys
import json
import requests
import time
import uuid
from urllib.parse import urlparse, parse_qs

# Add the parent directory to sys.path to allow importing the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from evrmore_authentication.auth import EvrmoreAuth
from evrmore_authentication.models import OAuthClient, OAuthToken

# These tests require a running authentication server
# You can use environment variables to configure the server URL
AUTH_SERVER = os.environ.get("TEST_AUTH_SERVER", "http://localhost:8000")

@pytest.fixture(scope="module")
def oauth_client():
    """Create a test OAuth client for testing."""
    # This is a destructive test, so we'll only run it if explicitly enabled
    if os.environ.get("ENABLE_E2E_TESTS") != "true":
        pytest.skip("End-to-end tests are disabled. Set ENABLE_E2E_TESTS=true to enable.")
        
    auth = EvrmoreAuth(debug=True)
    client = auth.register_oauth_client(
        client_name=f"Test Client {uuid.uuid4()}",
        redirect_uris=["http://localhost:9000/callback"],
        client_uri="http://localhost:9000",
        allowed_response_types=["code"],
        allowed_scopes=["profile", "email"]
    )
    yield client
    
    # Clean up after tests
    # This would delete the client, but it's skipped in this example
    # to avoid destructive operations in the test database

class TestOAuthFlow:
    """Test the complete OAuth 2.0 flow."""
    
    def test_client_registration(self, oauth_client):
        """Test that we can register an OAuth client."""
        assert oauth_client.client_id is not None
        assert oauth_client.client_secret is not None
        assert oauth_client.client_name.startswith("Test Client")
        assert "http://localhost:9000/callback" in oauth_client.redirect_uris
    
    def test_authorization_url(self, oauth_client):
        """Test generating an authorization URL."""
        # In a real test, we would:
        # 1. Generate authorization URL
        # 2. Extract state and other parameters
        # 3. Verify they're correctly formed
        pass
    
    def test_exchange_code(self, oauth_client):
        """Test exchanging an authorization code for tokens."""
        # In a real test, we would:
        # 1. Generate an authorization code
        # 2. Exchange it for tokens
        # 3. Verify the tokens work
        pass
    
    def test_refresh_token(self, oauth_client):
        """Test refreshing an access token."""
        # In a real test, we would:
        # 1. Get a refresh token
        # 2. Use it to get a new access token
        # 3. Verify the new token works
        pass
    
    def test_revoke_token(self, oauth_client):
        """Test revoking an access token."""
        # In a real test, we would:
        # 1. Get a token
        # 2. Revoke it
        # 3. Verify it no longer works
        pass 