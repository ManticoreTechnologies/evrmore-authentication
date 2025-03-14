import pytest
from unittest.mock import patch, MagicMock
import datetime

from evrmore_authentication import EvrmoreAuth
from evrmore_authentication.models import User, Session

@pytest.fixture
def auth():
    """Create an EvrmoreAuth instance with debug mode."""
    return EvrmoreAuth(debug=True)

@pytest.mark.parametrize("debug_mode", [True, False])
def test_initialization(debug_mode):
    """Test that EvrmoreAuth initializes correctly."""
    auth = EvrmoreAuth(debug=debug_mode)
    assert auth.debug is debug_mode

@patch('evrmore_authentication.auth.EvrmoreAuth.create_wallet_address')
@patch('evrmore_authentication.auth.EvrmoreAuth.generate_challenge')
@patch('evrmore_authentication.auth.EvrmoreAuth.sign_message')
@patch('evrmore_authentication.auth.EvrmoreAuth.authenticate')
@patch('evrmore_authentication.auth.EvrmoreAuth.validate_token')
def test_authentication_flow(mock_validate, mock_auth, mock_sign, mock_challenge, mock_create, auth):
    """Test the complete authentication flow."""
    # Setup mocks
    test_address = "EXAMPLEaddress123"
    test_wif = "private_key"
    test_challenge = "test_challenge"
    test_signature = "test_signature"
    test_token = "test_token"
    test_user_id = "test_user_id"
    
    mock_create.return_value = (test_address, test_wif)
    mock_challenge.return_value = test_challenge
    mock_sign.return_value = test_signature
    
    # Create mock session
    mock_session = MagicMock()
    mock_session.token = test_token
    mock_session.user_id = test_user_id
    mock_auth.return_value = mock_session
    
    mock_validate.return_value = {
        "user_id": test_user_id,
        "address": test_address
    }
    
    # Run the flow
    address, wif_key = auth.create_wallet_address()
    assert address == test_address
    assert wif_key == test_wif
    
    challenge = auth.generate_challenge(address)
    assert challenge == test_challenge
    
    signature = auth.sign_message(wif_key, challenge)
    assert signature == test_signature
    
    session = auth.authenticate(address, challenge, signature)
    assert session.token == test_token
    assert session.user_id == test_user_id
    
    verified = auth.validate_token(session.token)
    assert verified["user_id"] == test_user_id
    assert verified["address"] == test_address
    
    # Verify mock calls
    mock_create.assert_called_once()
    mock_challenge.assert_called_once_with(test_address)
    mock_sign.assert_called_once_with(test_wif, test_challenge)
    mock_auth.assert_called_once_with(test_address, test_challenge, test_signature)
    mock_validate.assert_called_once_with(test_token)



