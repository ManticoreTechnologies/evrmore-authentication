#!/usr/bin/env python3
"""
Evrmore Authentication Database Management Tool
--------------------------------------------
Manticore Technologies - https://manticore.technology

This script provides utilities for managing the Evrmore Authentication database.
"""

import os
import sys
import argparse
import logging
import json
import datetime
import uuid
from pathlib import Path
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-db-tool")

# Load environment variables
load_dotenv()

# Add the parent directory to the path
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import evrmore-authentication modules
from evrmore_authentication.models import (
    User, Challenge, Session, SQLiteManager,
    cleanup_expired_challenges, cleanup_expired_sessions,
    inspect_database_tables, check_database_integrity
)

def init_db():
    """Initialize the database."""
    logger.info("Initializing SQLite database...")

    # Just instantiate the manager to create tables
    db = SQLiteManager()
    
    # Print database path
    logger.info(f"Database initialized at: {os.environ.get('SQLITE_DB_PATH', './data/evrmore_auth.db')}")
    
    # Get table info
    tables = inspect_database_tables()
    logger.info(f"Created {len(tables)} tables:")
    
    for table_name, info in tables.items():
        logger.info(f"  - {table_name} ({len(info['columns'])} columns)")

def list_users(args):
    """List all users in the database."""
    db = SQLiteManager()
    users = db.fetchall("SELECT * FROM users")
    
    if not users:
        logger.info("No users found in the database.")
        return
    
    logger.info(f"Found {len(users)} users:")
    
    for user in users:
        if args.verbose:
            logger.info(f"  - ID: {user['id']}")
            logger.info(f"    Address: {user['evrmore_address']}")
            logger.info(f"    Username: {user['username'] or 'N/A'}")
            logger.info(f"    Email: {user['email'] or 'N/A'}")
            logger.info(f"    Active: {bool(user['is_active'])}")
            logger.info(f"    Created: {user['created_at']}")
            logger.info(f"    Last Login: {user['last_login'] or 'Never'}")
            logger.info("")
        else:
            logger.info(f"  - {user['evrmore_address']} (ID: {user['id'][:8]}...)")

def list_challenges(args):
    """List challenges in the database."""
    db = SQLiteManager()
    
    if args.address:
        # Find user by address
        user = User.get_by_address(args.address)
        if not user:
            logger.error(f"User with address {args.address} not found.")
            return
            
        challenges = Challenge.get_by_user_id(user.id)
        logger.info(f"Challenges for user {user.evrmore_address} (ID: {user.id}):")
    elif args.user_id:
        # Find challenges for user ID
        challenges = Challenge.get_by_user_id(args.user_id)
        logger.info(f"Challenges for user ID {args.user_id}:")
    else:
        # Get all challenges
        challenges = db.fetchall("SELECT * FROM challenges")
        logger.info(f"All challenges in the database:")
    
    if not challenges:
        logger.info("No challenges found.")
        return
        
    logger.info(f"Found {len(challenges)} challenges:")
    
    for challenge in challenges:
        if isinstance(challenge, Challenge):
            # If it's a Challenge object
            c_id = challenge.id
            u_id = challenge.user_id
            text = challenge.challenge_text
            expires = challenge.expires_at
            used = challenge.used
            created = challenge.created_at
        else:
            # If it's a database row
            c_id = challenge['id']
            u_id = challenge['user_id']
            text = challenge['challenge_text']
            expires = challenge['expires_at']
            used = bool(challenge['used'])
            created = challenge['created_at']
            
        if args.verbose:
            logger.info(f"  - ID: {c_id}")
            logger.info(f"    User ID: {u_id}")
            logger.info(f"    Text: {text}")
            logger.info(f"    Used: {used}")
            logger.info(f"    Created: {created}")
            logger.info(f"    Expires: {expires}")
            logger.info("")
        else:
            # Truncate challenge text for display
            short_text = text[:30] + "..." if len(text) > 30 else text
            logger.info(f"  - {short_text} (Used: {used}, User: {u_id[:8]}...)")

def list_sessions(args):
    """List sessions in the database."""
    db = SQLiteManager()
    
    if args.address:
        # Find user by address
        user = User.get_by_address(args.address)
        if not user:
            logger.error(f"User with address {args.address} not found.")
            return
            
        sessions = Session.get_by_user_id(user.id)
        logger.info(f"Sessions for user {user.evrmore_address} (ID: {user.id}):")
    elif args.user_id:
        # Find sessions for user ID
        sessions = Session.get_by_user_id(args.user_id)
        logger.info(f"Sessions for user ID {args.user_id}:")
    else:
        # Get all sessions
        sessions = db.fetchall("SELECT * FROM sessions")
        logger.info(f"All sessions in the database:")
    
    if not sessions:
        logger.info("No sessions found.")
        return
        
    logger.info(f"Found {len(sessions)} sessions:")
    
    for session in sessions:
        if isinstance(session, Session):
            # If it's a Session object
            s_id = session.id
            u_id = session.user_id
            token = session.token
            expires = session.expires_at
            active = session.is_active
            created = session.created_at
        else:
            # If it's a database row
            s_id = session['id']
            u_id = session['user_id']
            token = session['token']
            expires = session['expires_at']
            active = bool(session['is_active'])
            created = session['created_at']
            
        if args.verbose:
            logger.info(f"  - ID: {s_id}")
            logger.info(f"    User ID: {u_id}")
            logger.info(f"    Token: {token[:15]}...")
            logger.info(f"    Active: {active}")
            logger.info(f"    Created: {created}")
            logger.info(f"    Expires: {expires}")
            logger.info("")
        else:
            # Show token prefix
            token_prefix = token[:15] + "..." if token else "N/A"
            logger.info(f"  - {token_prefix} (Active: {active}, User: {u_id[:8]}...)")

def cleanup(args):
    """Clean up expired challenges and sessions."""
    if args.challenges or not args.sessions:
        challenges_count = cleanup_expired_challenges()
        logger.info(f"Removed {challenges_count} expired challenges.")
        
    if args.sessions or not args.challenges:
        sessions_count = cleanup_expired_sessions()
        logger.info(f"Removed {sessions_count} expired sessions.")

def create_user(args):
    """Create a new user."""
    evrmore_address = args.address
    
    # Check if user already exists
    existing_user = User.get_by_address(evrmore_address)
    if existing_user:
        logger.error(f"User with address {evrmore_address} already exists (ID: {existing_user.id}).")
        return
    
    # Create new user
    user = User(
        id=str(uuid.uuid4()),
        evrmore_address=evrmore_address,
        username=args.username,
        email=args.email
    )
    user.save()
    
    logger.info(f"Created new user:")
    logger.info(f"  - ID: {user.id}")
    logger.info(f"  - Address: {user.evrmore_address}")
    logger.info(f"  - Username: {user.username or 'N/A'}")
    logger.info(f"  - Email: {user.email or 'N/A'}")

def create_challenge(args):
    """Create a new challenge."""
    evrmore_address = args.address
    
    # Find or create user
    user = User.get_by_address(evrmore_address)
    if not user:
        if args.create_user:
            # Create a new user
            user = User(
                id=str(uuid.uuid4()),
                evrmore_address=evrmore_address
            )
            user.save()
            logger.info(f"Created new user with address: {evrmore_address} (ID: {user.id}).")
        else:
            logger.error(f"User with address {evrmore_address} not found. Use --create-user to create one.")
            return
    
    # Create challenge
    if args.custom_text:
        challenge_text = args.custom_text
    else:
        # Generate challenge text similar to the auth module
        timestamp = int(datetime.datetime.utcnow().timestamp())
        unique_id = os.urandom(4).hex()
        challenge_text = f"Sign this message to authenticate with Evrmore: {evrmore_address}:{timestamp}:{unique_id}"
    
    # Calculate expiry time
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=args.expire_minutes)
    
    # Create challenge in database
    challenge = Challenge(
        id=str(uuid.uuid4()),
        user_id=user.id,
        challenge_text=challenge_text,
        expires_at=expires_at,
        used=False
    )
    challenge.save()
    
    logger.info(f"Created new challenge:")
    logger.info(f"  - ID: {challenge.id}")
    logger.info(f"  - User ID: {user.id}")
    logger.info(f"  - Text: {challenge_text}")
    logger.info(f"  - Expires: {expires_at}")

def check_integrity(args):
    """Check database integrity."""
    results = check_database_integrity()
    
    logger.info("Database integrity check:")
    logger.info(f"  - Integrity check: {results['integrity_check']}")
    logger.info(f"  - Orphaned challenges: {results['orphaned_challenges']}")
    logger.info(f"  - Orphaned sessions: {results['orphaned_sessions']}")
    
    if args.fix and (results['orphaned_challenges'] > 0 or results['orphaned_sessions'] > 0):
        logger.info("Fixing orphaned records...")
        
        db = SQLiteManager()
        
        if results['orphaned_challenges'] > 0:
            db.execute("DELETE FROM challenges WHERE user_id NOT IN (SELECT id FROM users)")
            logger.info(f"  - Removed {results['orphaned_challenges']} orphaned challenges.")
            
        if results['orphaned_sessions'] > 0:
            db.execute("DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users)")
            logger.info(f"  - Removed {results['orphaned_sessions']} orphaned sessions.")

def show_info(args):
    """Show database information."""
    # Get database info
    tables = inspect_database_tables()
    
    # Print database path
    logger.info(f"Database path: {os.environ.get('SQLITE_DB_PATH', './data/evrmore_auth.db')}")
    
    # Print table info
    logger.info(f"Database contains {len(tables)} tables:")
    
    for table_name, info in tables.items():
        logger.info(f"  - {table_name}: {info['row_count']} rows")
        
        if args.verbose:
            logger.info(f"    Columns:")
            for col in info['columns']:
                pk = " (PK)" if col['pk'] else ""
                null = " NOT NULL" if col['notnull'] else ""
                logger.info(f"      - {col['name']}: {col['type']}{null}{pk}")
            logger.info("")

def reassign_challenge(args):
    """Reassign a challenge to a different user."""
    challenge_text = args.challenge_text
    new_address = args.new_address
    
    # Find challenge
    challenge = Challenge.get_by_text(challenge_text)
    if not challenge:
        logger.error(f"Challenge not found: {challenge_text}")
        return
        
    # Find original user
    original_user = User.get_by_id(challenge.user_id)
    original_address = original_user.evrmore_address if original_user else "Unknown"
    
    # Find or create new user
    new_user = User.get_by_address(new_address)
    if not new_user:
        if args.create_user:
            # Create a new user
            new_user = User(
                id=str(uuid.uuid4()),
                evrmore_address=new_address
            )
            new_user.save()
            logger.info(f"Created new user with address: {new_address} (ID: {new_user.id}).")
        else:
            logger.error(f"User with address {new_address} not found. Use --create-user to create one.")
            return
            
    # Update challenge
    challenge.user_id = new_user.id
    challenge.save()
    
    logger.info(f"Reassigned challenge:")
    logger.info(f"  - Challenge ID: {challenge.id}")
    logger.info(f"  - Text: {challenge.challenge_text}")
    logger.info(f"  - Original user: {original_address} (ID: {original_user.id if original_user else 'Unknown'})")
    logger.info(f"  - New user: {new_user.evrmore_address} (ID: {new_user.id})")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Evrmore Authentication Database Management Tool")
    subparsers = parser.add_subparsers(title="commands", dest="command")
    
    # Initialize database
    init_parser = subparsers.add_parser("init", help="Initialize database")
    
    # List users
    list_users_parser = subparsers.add_parser("list-users", help="List users")
    list_users_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    list_users_parser.set_defaults(func=list_users)
    
    # List challenges
    list_challenges_parser = subparsers.add_parser("list-challenges", help="List challenges")
    list_challenges_parser.add_argument("-a", "--address", help="Filter by Evrmore address")
    list_challenges_parser.add_argument("-u", "--user-id", help="Filter by user ID")
    list_challenges_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    list_challenges_parser.set_defaults(func=list_challenges)
    
    # List sessions
    list_sessions_parser = subparsers.add_parser("list-sessions", help="List sessions")
    list_sessions_parser.add_argument("-a", "--address", help="Filter by Evrmore address")
    list_sessions_parser.add_argument("-u", "--user-id", help="Filter by user ID")
    list_sessions_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    list_sessions_parser.set_defaults(func=list_sessions)
    
    # Cleanup
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up expired challenges and sessions")
    cleanup_parser.add_argument("-c", "--challenges", action="store_true", help="Clean up challenges only")
    cleanup_parser.add_argument("-s", "--sessions", action="store_true", help="Clean up sessions only")
    cleanup_parser.set_defaults(func=cleanup)
    
    # Create user
    create_user_parser = subparsers.add_parser("create-user", help="Create a new user")
    create_user_parser.add_argument("address", help="Evrmore address")
    create_user_parser.add_argument("-u", "--username", help="Username (optional)")
    create_user_parser.add_argument("-e", "--email", help="Email (optional)")
    create_user_parser.set_defaults(func=create_user)
    
    # Create challenge
    create_challenge_parser = subparsers.add_parser("create-challenge", help="Create a new challenge")
    create_challenge_parser.add_argument("address", help="Evrmore address")
    create_challenge_parser.add_argument("-t", "--custom-text", help="Custom challenge text")
    create_challenge_parser.add_argument("-e", "--expire-minutes", type=int, default=10, help="Minutes until challenge expires")
    create_challenge_parser.add_argument("--create-user", action="store_true", help="Create user if not exists")
    create_challenge_parser.set_defaults(func=create_challenge)
    
    # Check integrity
    check_integrity_parser = subparsers.add_parser("check-integrity", help="Check database integrity")
    check_integrity_parser.add_argument("--fix", action="store_true", help="Fix integrity issues")
    check_integrity_parser.set_defaults(func=check_integrity)
    
    # Show info
    info_parser = subparsers.add_parser("info", help="Show database information")
    info_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    info_parser.set_defaults(func=show_info)
    
    # Reassign challenge
    reassign_parser = subparsers.add_parser("reassign", help="Reassign a challenge to a different user")
    reassign_parser.add_argument("challenge_text", help="Challenge text")
    reassign_parser.add_argument("new_address", help="New Evrmore address")
    reassign_parser.add_argument("--create-user", action="store_true", help="Create user if not exists")
    reassign_parser.set_defaults(func=reassign_challenge)
    
    args = parser.parse_args()
    
    if args.command == "init":
        init_db()
    elif hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 