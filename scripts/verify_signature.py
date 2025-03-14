#!/usr/bin/env python3
"""
Evrmore Signature Verification Tool
--------------------------------------------
Manticore Technologies - https://manticore.technology

This script verifies Evrmore signatures without requiring database interactions.
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-verify-tool")

# Load environment variables
load_dotenv()

# Add the parent directory to the path
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import evrmore-authentication modules
from evrmore_authentication.crypto import verify_message, sign_message
from evrmore_authentication.auth import EvrmoreAuth

def verify_signature(args):
    """Verify a signature."""
    address = args.address
    message = args.message
    signature = args.signature
    
    logger.info(f"Verifying signature for address: {address}")
    logger.info(f"Message: {message}")
    logger.info(f"Signature length: {len(signature)}")
    
    # Create auth instance just for verification
    auth = EvrmoreAuth(debug=True)
    
    # Use the direct verification method
    result = auth.verify_signature_only(address, message, signature)
    
    if result:
        logger.info("✅ Signature verification SUCCESSFUL")
        return 0
    else:
        logger.error("❌ Signature verification FAILED")
        return 1

def generate_signature(args):
    """Generate a signature for testing."""
    private_key = args.private_key
    message = args.message
    
    logger.info(f"Generating signature for message: {message}")
    
    # Sign the message
    try:
        signature = sign_message(message, private_key)
        logger.info(f"✅ Signature created: {signature}")
        logger.info(f"Signature length: {len(signature)}")
        return 0
    except Exception as e:
        logger.error(f"❌ Error generating signature: {str(e)}")
        return 1

def generate_challenge(args):
    """Generate a challenge string in the same format as the auth system."""
    address = args.address
    
    # Create auth instance (no database interaction)
    auth = EvrmoreAuth()
    
    # Use the internal method
    challenge_text = auth._create_challenge_text(address)
    
    logger.info(f"Generated challenge for address {address}:")
    logger.info(f"{challenge_text}")
    
    return 0

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Evrmore Signature Verification Tool")
    subparsers = parser.add_subparsers(dest="command")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signature")
    verify_parser.add_argument("address", help="Evrmore address that signed the message")
    verify_parser.add_argument("message", help="Message that was signed")
    verify_parser.add_argument("signature", help="Signature to verify")
    verify_parser.set_defaults(func=verify_signature)
    
    # Sign command (for testing)
    sign_parser = subparsers.add_parser("sign", help="Generate a signature (for testing)")
    sign_parser.add_argument("private_key", help="Private key (WIF format)")
    sign_parser.add_argument("message", help="Message to sign")
    sign_parser.set_defaults(func=generate_signature)
    
    # Challenge command
    challenge_parser = subparsers.add_parser("challenge", help="Generate a challenge string")
    challenge_parser.add_argument("address", help="Evrmore address to generate challenge for")
    challenge_parser.set_defaults(func=generate_challenge)
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        sys.exit(args.func(args))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main() 