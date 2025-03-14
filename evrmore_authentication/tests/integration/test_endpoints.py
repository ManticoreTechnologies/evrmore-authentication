import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from evrmore_authentication.api import app

# Create a test client
client = TestClient(app)

@pytest.fixture
def mock_auth():
    """Mock EvrmoreAuth for API testing."""
    with patch('evrmore_authentication.api.auth') as mock_auth:
        mock_auth.debug = True
        mock_auth.validate_token.return_value = {
            "user_id": "test_user_id",
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