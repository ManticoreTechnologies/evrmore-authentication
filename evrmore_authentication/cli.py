"""Command-line interface for Evrmore Authentication.

This module provides a command-line interface for managing
the Evrmore Authentication system.
"""

import os
import sys
import argparse
import datetime
import uuid
from typing import List, Optional
import getpass

from sqlalchemy.exc import SQLAlchemyError
from .db import get_db, init_db
from .models import User, Session
from .auth import EvrmoreAuth

def setup_parser() -> argparse.ArgumentParser:
    """Set up the argument parser.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Evrmore Authentication CLI",
        prog="evrmore-auth"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # init command
    init_parser = subparsers.add_parser("init", help="Initialize the database")
    
    # user commands
    user_parser = subparsers.add_parser("user", help="User management")
    user_subparsers = user_parser.add_subparsers(dest="user_command", help="User command")
    
    # user list
    user_list_parser = user_subparsers.add_parser("list", help="List users")
    
    # user create
    user_create_parser = user_subparsers.add_parser("create", help="Create a user")
    user_create_parser.add_argument("--address", required=True, help="Evrmore wallet address")
    user_create_parser.add_argument("--username", help="Username (optional)")
    user_create_parser.add_argument("--email", help="Email address (optional)")
    
    # user delete
    user_delete_parser = user_subparsers.add_parser("delete", help="Delete a user")
    user_delete_parser.add_argument("--address", help="Evrmore wallet address")
    user_delete_parser.add_argument("--username", help="Username")
    user_delete_parser.add_argument("--id", help="User ID")
    
    # session commands
    session_parser = subparsers.add_parser("session", help="Session management")
    session_subparsers = session_parser.add_subparsers(dest="session_command", help="Session command")
    
    # session list
    session_list_parser = session_subparsers.add_parser("list", help="List sessions")
    session_list_parser.add_argument("--address", help="Filter by Evrmore wallet address")
    
    # session revoke
    session_revoke_parser = session_subparsers.add_parser("revoke", help="Revoke a session")
    session_revoke_parser.add_argument("--id", required=True, help="Session ID to revoke")
    
    # test commands
    test_parser = subparsers.add_parser("test", help="Test utilities")
    test_subparsers = test_parser.add_subparsers(dest="test_command", help="Test command")
    
    # test connection
    test_connection_parser = test_subparsers.add_parser("connection", help="Test Evrmore RPC connection")
    
    return parser

def init_command():
    """Initialize the database."""
    try:
        init_db()
        print("Database initialized successfully")
        return 0
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        return 1

def user_list_command():
    """List all users."""
    try:
        db = next(get_db())
        users = db.query(User).all()
        
        if not users:
            print("No users found")
            return 0
        
        print(f"Found {len(users)} users:")
        for user in users:
            print(f"ID: {user.id}")
            print(f"  Address: {user.evrmore_address}")
            if user.username:
                print(f"  Username: {user.username}")
            if user.email:
                print(f"  Email: {user.email}")
            print(f"  Created: {user.created_at}")
            print(f"  Last login: {user.last_login or 'Never'}")
            print("")
        
        return 0
    except Exception as e:
        print(f"Error listing users: {str(e)}")
        return 1

def user_create_command(address: str, username: Optional[str] = None, email: Optional[str] = None):
    """Create a new user.
    
    Args:
        address (str): Evrmore wallet address
        username (Optional[str], optional): Username. Defaults to None.
        email (Optional[str], optional): Email address. Defaults to None.
        
    Returns:
        int: Exit code
    """
    try:
        db = next(get_db())
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.evrmore_address == address).first()
        if existing_user:
            print(f"User with address {address} already exists")
            return 1
        
        # Create new user
        user = User(
            evrmore_address=address,
            username=username,
            email=email
        )
        
        db.add(user)
        db.commit()
        
        print(f"User created successfully (ID: {user.id})")
        return 0
    except Exception as e:
        print(f"Error creating user: {str(e)}")
        return 1

def user_delete_command(address: Optional[str] = None, username: Optional[str] = None, user_id: Optional[str] = None):
    """Delete a user.
    
    Args:
        address (Optional[str], optional): Evrmore wallet address. Defaults to None.
        username (Optional[str], optional): Username. Defaults to None.
        user_id (Optional[str], optional): User ID. Defaults to None.
        
    Returns:
        int: Exit code
    """
    try:
        db = next(get_db())
        
        # Find the user
        query = db.query(User)
        if address:
            query = query.filter(User.evrmore_address == address)
        elif username:
            query = query.filter(User.username == username)
        elif user_id:
            query = query.filter(User.id == user_id)
        else:
            print("Please provide one of: --address, --username, or --id")
            return 1
        
        user = query.first()
        if not user:
            print("User not found")
            return 1
        
        # Confirm deletion
        print(f"About to delete user:")
        print(f"ID: {user.id}")
        print(f"Address: {user.evrmore_address}")
        if user.username:
            print(f"Username: {user.username}")
        
        confirm = input("Are you sure? (y/N): ")
        if confirm.lower() != "y":
            print("Operation cancelled")
            return 0
        
        # Delete user
        db.delete(user)
        db.commit()
        
        print("User deleted successfully")
        return 0
    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        return 1

def session_list_command(address: Optional[str] = None):
    """List active sessions.
    
    Args:
        address (Optional[str], optional): Evrmore wallet address filter. Defaults to None.
        
    Returns:
        int: Exit code
    """
    try:
        db = next(get_db())
        
        # Build the query
        query = db.query(Session).filter(Session.is_active == True)
        
        if address:
            # Join with User to filter by address
            query = query.join(User).filter(User.evrmore_address == address)
        
        sessions = query.all()
        
        if not sessions:
            print("No active sessions found")
            return 0
        
        print(f"Found {len(sessions)} active sessions:")
        for session in sessions:
            print(f"ID: {session.id}")
            print(f"  User ID: {session.user_id}")
            user = db.query(User).filter(User.id == session.user_id).first()
            if user:
                print(f"  Evrmore Address: {user.evrmore_address}")
                if user.username:
                    print(f"  Username: {user.username}")
            print(f"  Created: {session.created_at}")
            print(f"  Expires: {session.expires_at}")
            if session.ip_address:
                print(f"  IP Address: {session.ip_address}")
            print("")
        
        return 0
    except Exception as e:
        print(f"Error listing sessions: {str(e)}")
        return 1

def session_revoke_command(session_id: str):
    """Revoke a session.
    
    Args:
        session_id (str): Session ID to revoke
        
    Returns:
        int: Exit code
    """
    try:
        db = next(get_db())
        
        # Find the session
        session = db.query(Session).filter(Session.id == session_id).first()
        if not session:
            print("Session not found")
            return 1
        
        # Revoke the session
        session.is_active = False
        db.commit()
        
        print("Session revoked successfully")
        return 0
    except Exception as e:
        print(f"Error revoking session: {str(e)}")
        return 1

def test_connection_command():
    """Test the Evrmore RPC connection."""
    try:
        auth = EvrmoreAuth()
        
        # Test the connection by getting blockchain info
        info = auth.evrmore_rpc.getblockchaininfo()
        
        print("Connection successful!")
        print(f"Chain: {info.get('chain', 'unknown')}")
        print(f"Blocks: {info.get('blocks', 'unknown')}")
        
        return 0
    except Exception as e:
        print(f"Connection failed: {str(e)}")
        return 1

def main():
    """Main entry point for the CLI."""
    parser = setup_parser()
    args = parser.parse_args()
    
    # No command provided
    if not args.command:
        parser.print_help()
        return 1
    
    # Process commands
    if args.command == "init":
        return init_command()
    
    elif args.command == "user":
        if not args.user_command:
            return 1
            
        if args.user_command == "list":
            return user_list_command()
        elif args.user_command == "create":
            return user_create_command(args.address, args.username, args.email)
        elif args.user_command == "delete":
            return user_delete_command(args.address, args.username, args.id)
    
    elif args.command == "session":
        if not args.session_command:
            return 1
            
        if args.session_command == "list":
            return session_list_command(args.address)
        elif args.session_command == "revoke":
            return session_revoke_command(args.id)
    
    elif args.command == "test":
        if not args.test_command:
            return 1
            
        if args.test_command == "connection":
            return test_connection_command()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 