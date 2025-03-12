#!/usr/bin/env python3
"""
Manual Test Script for Evrmore Authentication

This script allows you to manually test the Evrmore Authentication system
with a real Evrmore node. It provides a command-line interface for generating
challenges, signing messages, and verifying signatures.

Usage:
  python3 manual_test.py [command] [options]
"""

import os
import sys
import datetime
import argparse
import uuid

# Set environment variables for testing
os.environ["JWT_SECRET"] = "test-secret-key-not-for-production"

from evrmore_authentication import EvrmoreAuth 
from evrmore_authentication.exceptions import (
    AuthenticationError,
    InvalidSignatureError,
    ChallengeExpiredError,
    UserNotFoundError
)

def setup_parser():
    """Set up the argument parser."""
    parser = argparse.ArgumentParser(
        description="Evrmore Authentication Manual Test",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # generate command
    generate_parser = subparsers.add_parser("generate", help="Generate a challenge for an address")
    generate_parser.add_argument("--address", required=True, help="Evrmore address to generate challenge for")
    
    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signature")
    verify_parser.add_argument("--address", required=True, help="Evrmore address")
    verify_parser.add_argument("--challenge", required=True, help="Challenge text")
    verify_parser.add_argument("--signature", required=True, help="Signature")
    
    # direct command
    direct_parser = subparsers.add_parser("direct", help="Direct verification using Evrmore RPC")
    direct_parser.add_argument("--address", required=True, help="Evrmore address")
    direct_parser.add_argument("--message", required=True, help="Message to verify")
    direct_parser.add_argument("--signature", required=True, help="Signature")
    
    # interactive command
    interactive_parser = subparsers.add_parser("interactive", help="Interactive test mode")
    
    return parser

def command_generate(address):
    """Generate a challenge for an address."""
    try:
        auth = EvrmoreAuth()
        challenge = auth.generate_challenge(address)
        
        print("\nGenerated challenge:")
        print("-" * 80)
        print(challenge)
        print("-" * 80)
        
        print("\nTo sign this challenge with Evrmore CLI:")
        print(f"evrmore-cli signmessage {address} \"{challenge}\"")
        
        return 0
    except Exception as e:
        print(f"Error generating challenge: {e}")
        return 1

def command_verify(address, challenge, signature):
    """Verify a signature."""
    try:
        auth = EvrmoreAuth()
        
        print("Verifying signature...")
        user_session = auth.authenticate(
            evrmore_address=address,
            challenge=challenge,
            signature=signature
        )
        
        print("\n✅ Signature verified successfully!")
        print(f"User ID: {user_session.user_id}")
        print(f"Expires: {user_session.expires_at}")
        print(f"Token: {user_session.token[:30]}...")
        
        return 0
    except InvalidSignatureError:
        print("\n❌ Invalid signature")
        return 1
    except ChallengeExpiredError:
        print("\n❌ Challenge has expired")
        return 1
    except UserNotFoundError:
        print("\n❌ User not found")
        return 1
    except Exception as e:
        print(f"\n❌ Error verifying signature: {e}")
        return 1

def command_direct(address, message, signature):
    """Directly verify a signature using Evrmore RPC."""
    try:
        auth = EvrmoreAuth()
        
        print("Directly verifying signature using Evrmore RPC...")
        result = auth.verify_signature(
            address,
            message,
            signature
        )
        
        if result:
            print("\n✅ Signature is valid!")
        else:
            print("\n❌ Signature is invalid!")
        
        return 0 if result else 1
    except Exception as e:
        print(f"\n❌ Error verifying signature: {e}")
        return 1

def command_interactive():
    """Run in interactive mode."""
    try:
        auth = EvrmoreAuth()
        
        print("Evrmore Authentication Interactive Test")
        print("======================================")
        
        # Get Evrmore address
        address = input("\nEnter Evrmore address: ").strip()
        if not address:
            print("No address provided. Exiting.")
            return 1
        
        # Generate challenge
        challenge = auth.generate_challenge(address)
        print("\nGenerated challenge:")
        print("-" * 80)
        print(challenge)
        print("-" * 80)
        
        print("\nTo sign this challenge with Evrmore CLI:")
        print(f"evrmore-cli signmessage {address} \"{challenge}\"")
        
        # Get signature
        signature = input("\nEnter signature (or press Enter to exit): ").strip()
        if not signature:
            print("No signature provided. Exiting.")
            return 0
        
        # Verify signature
        try:
            user_session = auth.authenticate(
                evrmore_address=address,
                challenge=challenge,
                signature=signature
            )
            
            print("\n✅ Signature verified successfully!")
            print(f"User ID: {user_session.user_id}")
            print(f"Expires: {user_session.expires_at}")
            print(f"Token: {user_session.token[:30]}...")
            
        except InvalidSignatureError:
            print("\n❌ Invalid signature")
            return 1
        except ChallengeExpiredError:
            print("\n❌ Challenge has expired")
            return 1
        except Exception as e:
            print(f"\n❌ Error verifying signature: {e}")
            return 1
        
        return 0
    except Exception as e:
        print(f"Error in interactive mode: {e}")
        return 1

def main():
    """Main entry point."""
    parser = setup_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == "generate":
        return command_generate(args.address)
    
    elif args.command == "verify":
        return command_verify(args.address, args.challenge, args.signature)
    
    elif args.command == "direct":
        return command_direct(args.address, args.message, args.signature)
    
    elif args.command == "interactive":
        return command_interactive()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 