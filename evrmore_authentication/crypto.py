"""
Evrmore Cryptographic Functions

This module provides functions for Evrmore signature creation and verification
without requiring an Evrmore node.
"""

import base64
import base58
from hashlib import sha256
from Crypto.Hash import RIPEMD160
from coincurve import PrivateKey, PublicKey
from typing import Tuple, Optional


def evrmore_message_hash(message: str) -> bytes:
    """
    Create a hash of a message for signing in Evrmore format.
    
    Args:
        message: The message to hash
        
    Returns:
        bytes: Double SHA-256 hash of the formatted message
    """
    prefix = b"Evrmore Signed Message:\n"
    
    def varint(n):
        if n < 253:
            return bytes([n])
        elif n < 0x10000:
            return b'\xfd' + n.to_bytes(2, 'little')
        elif n < 0x100000000:
            return b'\xfe' + n.to_bytes(4, 'little')
        else:
            return b'\xff' + n.to_bytes(8, 'little')

    prefix_bytes = varint(len(prefix)) + prefix
    message_bytes = varint(len(message)) + message.encode('utf-8')
    to_hash = prefix_bytes + message_bytes
    return sha256(sha256(to_hash).digest()).digest()


def wif_to_privkey(wif: str) -> bytes:
    """
    Convert a WIF private key to raw bytes.
    
    Args:
        wif: The WIF-encoded private key
        
    Returns:
        bytes: Raw private key bytes
        
    Raises:
        ValueError: If the WIF format is invalid
    """
    decoded = base58.b58decode_check(wif)
    if decoded[0] != 0x80:
        raise ValueError("Invalid WIF prefix")
    return decoded[1:33]


def pubkey_to_address(pubkey: bytes) -> str:
    """
    Convert a public key to an Evrmore address.
    
    Args:
        pubkey: Raw public key bytes
        
    Returns:
        str: Evrmore address
    """
    sha = sha256(pubkey).digest()
    ripe = RIPEMD160.new(sha).digest()
    versioned = b'\x21' + ripe  # Evrmore mainnet P2PKH prefix 0x21
    checksum = sha256(sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()


def sign_message(message: str, wif_privkey: str) -> str:
    """
    Sign a message with an Evrmore private key.
    
    Args:
        message: The message to sign
        wif_privkey: WIF-encoded private key
        
    Returns:
        str: Base64-encoded signature
        
    Raises:
        ValueError: If the WIF key is invalid
    """
    privkey = PrivateKey(wif_to_privkey(wif_privkey))
    msg_hash = evrmore_message_hash(message)
    
    signature_full = privkey.sign_recoverable(msg_hash, hasher=None)
    
    # signature_full[-1] is the recid, signature_full[:-1] is r+s
    signature, recid = signature_full[:64], signature_full[64]
    
    # Correct header byte calculation:
    header_byte = 27 + recid + 4  # 4 is added because we're using compressed keys
    
    sig_compact = bytes([header_byte]) + signature
    return base64.b64encode(sig_compact).decode()


def verify_message(address: str, signature_b64: str, message: str) -> bool:
    """
    Verify an Evrmore message signature.
    
    Args:
        address: The Evrmore address that supposedly signed the message
        signature_b64: Base64-encoded signature
        message: The message that was signed
        
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    try:
        sig_compact = base64.b64decode(signature_b64)
        if len(sig_compact) != 65:
            return False
        
        header = sig_compact[0]
        
        if header < 27 or header > 34:
            return False
        
        recid = (header - 27) & 3
        compressed = ((header - 27) & 4) != 0
        
        msg_hash = evrmore_message_hash(message)
        
        pubkey = PublicKey.from_signature_and_message(
            sig_compact[1:] + bytes([recid]), 
            msg_hash, 
            hasher=None
        )
        pubkey_bytes = pubkey.format(compressed=compressed)
        derived_address = pubkey_to_address(pubkey_bytes)
        return derived_address == address
    except Exception:
        return False


def generate_key_pair() -> Tuple[str, str]:
    """
    Generate a new Evrmore private key and address.
    
    Returns:
        Tuple[str, str]: (WIF private key, Evrmore address)
    """
    privkey = PrivateKey()
    
    # Convert to WIF format
    key_bytes = privkey.secret
    extended = b'\x80' + key_bytes + b'\x01'  # Mainnet prefix + compressed flag
    checksum = sha256(sha256(extended).digest()).digest()[:4]
    wif = base58.b58encode(extended + checksum).decode()
    
    # Get address
    pubkey = privkey.public_key.format(compressed=True)
    address = pubkey_to_address(pubkey)
    
    return wif, address 