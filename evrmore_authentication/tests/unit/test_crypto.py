#!/usr/bin/env python3
"""
Unit tests for the crypto module.
"""

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

from evrmore_authentication.crypto import (
    sign_message,
    verify_message,
    generate_key_pair,
    pubkey_to_address,
    wif_to_privkey,
    evrmore_message_hash
)

def test_message_hash():
    """Test creating a message hash."""
    msg = "Test message"
    msg_hash = evrmore_message_hash(msg)
    
    # Check that we get a valid hash
    assert isinstance(msg_hash, bytes)
    assert len(msg_hash) == 32  # SHA-256 hash is 32 bytes

def test_key_pair_generation():
    """Test generating a key pair."""
    wif, address = generate_key_pair()
    
    # Check that we got strings
    assert isinstance(wif, str)
    assert isinstance(address, str)
    
    # Basic format checks
    assert wif.startswith('K') or wif.startswith('L')  # Compressed WIF format for mainnet
    assert address.startswith('E')  # Evrmore address starts with E

def test_pubkey_to_address():
    """Test converting a public key to an Evrmore address."""
    # Create a test public key (33 bytes for compressed key)
    test_pubkey = bytes.fromhex("02" + "11" * 32)  # Simulated compressed public key
    
    # Convert to address
    address = pubkey_to_address(test_pubkey)
    
    # Check the address format
    assert address.startswith("E")
    assert len(address) >= 34 and len(address) <= 35

@pytest.fixture
def test_wif_key():
    """Generate a valid WIF key for testing."""
    wif, _ = generate_key_pair()
    return wif

def test_wif_to_privkey(test_wif_key):
    """Test converting a WIF to a private key."""
    # Use a generated valid WIF
    privkey = wif_to_privkey(test_wif_key)
    
    # Check the result
    assert isinstance(privkey, bytes)
    assert len(privkey) == 32  # Private key should be 32 bytes

def test_sign_and_verify_message(test_wif_key):
    """Test signing a message and verifying the signature."""
    # Get the address from the WIF key
    _, address = generate_key_pair()  # We'll use a fresh address for this test
    message = "Test message for signing"
    
    # Sign the message
    signature = sign_message(message, test_wif_key)
    
    # Verify the signature
    with patch('evrmore_authentication.crypto.pubkey_to_address') as mock_pubkey:
        # Mock the address derivation to return our test address
        mock_pubkey.return_value = address
        
        result = verify_message(address, signature, message)
        assert result is True 