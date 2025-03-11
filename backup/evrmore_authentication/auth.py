"""Core authentication module for Evrmore Authentication.

This module provides the main functionality for authentication using
Evrmore wallet signatures.
"""

import os
import uuid
import datetime
import secrets
import logging
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import jwt
from evrmore_rpc import EvrmoreClient

from .db import get_db
from .models import User, Challenge, Session as DBSession
from .exceptions import (
    AuthenticationError,
    ChallengeExpiredError,
    InvalidSignatureError,
    UserNotFoundError,
    SessionExpiredError,
    InvalidTokenError,
    ChallengeAlreadyUsedError,
    ConfigurationError
)

# Set up logging
logger = logging.getLogger(__name__)

# Environment variables for configuration
EVRMORE_RPC_HOST = os.getenv("EVRMORE_RPC_HOST", "localhost")
EVRMORE_RPC_PORT = int(os.getenv("EVRMORE_RPC_PORT", "8819"))
EVRMORE_RPC_USER = os.getenv("EVRMORE_RPC_USER", "")
EVRMORE_RPC_PASSWORD = os.getenv("EVRMORE_RPC_PASSWORD", "")
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
CHALLENGE_EXPIRE_MINUTES = int(os.getenv("CHALLENGE_EXPIRE_MINUTES", "10"))

# If JWT_SECRET not provided, generate a consistent one for the session
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)
    logger.warning("JWT_SECRET not set in environment. Using a generated value for this session.")

@dataclass
class UserSession:
    """Data class representing a user's session."""
    user_id: str
    evrmore_address: str
    token: str
    expires_at: datetime.datetime


class EvrmoreAuth:
    """Core authentication class for Evrmore wallet-based authentication."""
    
    # Class attribute to track if Evrmore node is available
    evrmore_available = False
    
    def __init__(self, db=None):
        """Initialize the Evrmore Authentication system.
        
        Args:
            db: Redis client instance
                If not provided, a new client will be created when needed.
        """
        self.db = db
        self.jwt_secret = JWT_SECRET
            
        # Initialize Evrmore RPC connection
        try:
            # Use EvrmoreClient from evrmore_rpc library
            # This will auto-configure from evrmore.conf if no credentials are provided
            self.evrmore_client = EvrmoreClient()
            
            # Test connection by getting blockchain info
            self.evrmore_client.getblockchaininfo()
            logger.info("Successfully connected to Evrmore node")
            EvrmoreAuth.evrmore_available = True
            
        except Exception as e:
            logger.error(f"Failed to initialize Evrmore RPC: {str(e)}")
            EvrmoreAuth.evrmore_available = False
            self.evrmore_client = None
            raise ConfigurationError(f"Evrmore RPC initialization failed: {str(e)}")
    
    def _get_db(self):
        """Get a database connection.
        
        Returns:
            Redis client
        """
        if self.db is not None:
            return self.db
        
        from .db import get_db
        return get_db()

    def generate_challenge(self, evrmore_address, expire_minutes=CHALLENGE_EXPIRE_MINUTES):
        """Generate a challenge for a user to sign with their Evrmore wallet.
        
        Args:
            evrmore_address (str): The user's Evrmore address
            expire_minutes (int, optional): Minutes until challenge expires
                Defaults to CHALLENGE_EXPIRE_MINUTES from environment.
                
        Returns:
            str: The challenge text
            
        Raises:
            ConfigurationError: If the system is not properly configured
        """
        from .db import create_user, create_challenge, get_user_by_address
        
        # Ensure evrmore_address is lowercase for consistency
        evrmore_address = evrmore_address.lower()
        
        # Get or create user
        user_data = get_user_by_address(evrmore_address)
        if not user_data:
            # Create new user
            user_data = create_user(evrmore_address)
        
        # Generate challenge text
        challenge_text = self._create_challenge_text(evrmore_address)
        
        # Set expiration time
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
        
        # Create challenge record
        challenge_data = create_challenge(
            user_id=user_data["id"],
            challenge_text=challenge_text,
            expires_at=expires_at
        )
        
        # Return challenge text
        return challenge_text

    def authenticate(
        self, 
        evrmore_address, 
        challenge, 
        signature,
        ip_address=None,
        user_agent=None,
        token_expire_minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    ):
        """Authenticate a user using their signed challenge.
        
        Args:
            evrmore_address (str): The user's Evrmore address
            challenge (str): The challenge text that was signed
            signature (str): The signature provided by the user
            ip_address (str, optional): Client IP address
            user_agent (str, optional): Client user agent
            token_expire_minutes (int, optional): Minutes until token expires
                Defaults to JWT_ACCESS_TOKEN_EXPIRE_MINUTES from environment.
                
        Returns:
            UserSession: Session information including token
            
        Raises:
            UserNotFoundError: If the user does not exist
            ChallengeExpiredError: If the challenge has expired
            InvalidSignatureError: If the signature is invalid
            ChallengeAlreadyUsedError: If the challenge has already been used
            ConfigurationError: If the system is not properly configured
        """
        from .db import (
            get_user_by_address, 
            get_challenge_by_text, 
            mark_challenge_used,
            create_session
        )
        
        # Ensure evrmore_address is lowercase for consistency
        evrmore_address = evrmore_address.lower()
        
        # Get user
        user_data = get_user_by_address(evrmore_address)
        if not user_data:
            raise UserNotFoundError(evrmore_address)
        
        # Get challenge
        challenge_data = get_challenge_by_text(challenge)
        if not challenge_data:
            raise ChallengeExpiredError()
        
        # Check if challenge belongs to user
        if challenge_data["user_id"] != user_data["id"]:
            logger.warning(
                f"Challenge mismatch: {challenge_data['user_id']} != {user_data['id']}"
            )
            raise InvalidSignatureError(evrmore_address)
        
        # Check if challenge has expired
        challenge_obj = Challenge.from_dict(challenge_data)
        if challenge_obj.is_expired:
            logger.warning(f"Challenge expired: {challenge_obj.expires_at}")
            raise ChallengeExpiredError(challenge_obj.id)
        
        # Check if challenge has already been used
        if challenge_data["used"]:
            logger.warning(f"Challenge already used: {challenge_obj.id}")
            raise ChallengeAlreadyUsedError(challenge_obj.id)
        
        # Verify signature
        if not self.verify_signature(evrmore_address, challenge, signature):
            logger.warning(f"Invalid signature for {evrmore_address}")
            logger.warning(f"Challenge: '{challenge}'")
            logger.warning(f"Signature: '{signature}'")
            logger.warning(f"Address: '{evrmore_address}'")
            # Try direct verification for debugging
            try:
                direct_result = self.evrmore_client.verifymessage(evrmore_address, signature, challenge)
                logger.warning(f"Direct verification result: {direct_result}")
            except Exception as e:
                logger.warning(f"Direct verification error: {str(e)}")
            raise InvalidSignatureError(evrmore_address)
        
        # Mark challenge as used
        mark_challenge_used(challenge_data["id"])
        
        # Generate token expiry time
        token_expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expire_minutes)
        
        # Create JWT token with expiration
        token_id = str(uuid.uuid4())
        user_id = str(user_data["id"])
        payload = {
            "sub": user_id,  # subject (user id)
            "addr": evrmore_address,  # evrmore address
            "exp": int(token_expires.timestamp()),  # expiration time
            "iat": int(datetime.datetime.utcnow().timestamp()),  # issued at
            "jti": token_id  # JWT ID
        }
        
        token = jwt.encode(
            payload,
            self.jwt_secret,
            algorithm=JWT_ALGORITHM
        )
        
        # Create session record
        create_session(
            user_id=user_id,
            token=token,
            expires_at=token_expires,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Update last login time
        from .db import update_user
        update_user(user_id, last_login=datetime.datetime.utcnow())
        
        # Return user session info
        return UserSession(
            user_id=user_id,
            evrmore_address=evrmore_address,
            token=token,
            expires_at=token_expires
        )

    def validate_token(self, token):
        """Validate a JWT token.
        
        Args:
            token (str): The JWT token to validate
            
        Returns:
            dict: The decoded token payload if valid
            
        Raises:
            InvalidTokenError: If the token is invalid, expired, or has been revoked
        """
        from .db import get_session_by_token
        
        try:
            print(f"Using JWT secret: {self.jwt_secret[:5]}...")
            # Decode the token
            payload = jwt.decode(token, self.jwt_secret, algorithms=[JWT_ALGORITHM])
            print(f"Token data: {payload}")
            
            # Check if token has been invalidated
            session_data = get_session_by_token(token)
            if not session_data or not session_data["is_active"]:
                logger.warning(f"Token validation failed: Token has been invalidated")
                raise InvalidTokenError("Token has been invalidated")
            
            # If we got here, token is valid
            return payload
            
        except jwt.PyJWTError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            raise InvalidTokenError(f"Token validation failed: {str(e)}")

    def get_user_by_token(self, token):
        """Get the user associated with a token.
        
        Args:
            token (str): The JWT token
            
        Returns:
            User: The user associated with the token
            
        Raises:
            InvalidTokenError: If the token is invalid
            UserNotFoundError: If the user does not exist
        """
        from .db import get_user_by_id
        
        # Validate token first
        payload = self.validate_token(token)
        
        # Get user ID from token
        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError("Token does not contain user ID")
        
        # Get user
        user_data = get_user_by_id(user_id)
        if not user_data:
            raise UserNotFoundError(user_id)
        
        # Return user object
        return User.from_dict(user_data)

    def invalidate_token(self, token):
        """Invalidate a JWT token (logout).
        
        Args:
            token (str): The JWT token to invalidate
            
        Returns:
            bool: True if successful, False otherwise
        """
        from .db import get_session_by_token, invalidate_session
        
        try:
            # Get session by token
            session_data = get_session_by_token(token)
            if not session_data:
                logger.warning(f"Token not found: {token[:10]}...")
                return False
            
            # Invalidate session
            invalidate_session(session_data["id"])
            
            return True
            
        except Exception as e:
            logger.error(f"Error invalidating token: {str(e)}")
            return False

    def invalidate_all_tokens(self, user_id):
        """Invalidate all tokens for a user.
        
        Args:
            user_id (str): The user ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        from .db import invalidate_all_sessions
        
        try:
            # Convert UUID to string if needed
            user_id = str(user_id)
            
            # Invalidate all sessions for user
            count = invalidate_all_sessions(user_id)
            
            logger.info(f"Invalidated {count} tokens for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error invalidating all tokens: {str(e)}")
            return False

    def create_wallet_address(self):
        """Create a new Evrmore wallet address.
        
        Returns:
            str: New Evrmore address
            
        Raises:
            ConfigurationError: If the Evrmore client is not available
        """
        if not EvrmoreAuth.evrmore_available:
            raise ConfigurationError("Evrmore node is not available")
        
        try:
            # Call getnewaddress RPC method
            address = self.evrmore_client.getnewaddress()
            return address
            
        except Exception as e:
            logger.error(f"Error creating wallet address: {str(e)}")
            raise ConfigurationError(f"Failed to create wallet address: {str(e)}")

    def sign_message(self, address, message):
        """Sign a message with an Evrmore wallet address.
        
        Args:
            address (str): The Evrmore address to sign with
            message (str): The message to sign
            
        Returns:
            str: The signature
            
        Raises:
            ConfigurationError: If the Evrmore client is not available
        """
        if not EvrmoreAuth.evrmore_available:
            raise ConfigurationError("Evrmore node is not available")
        
        try:
            # Call signmessage RPC method
            signature = self.evrmore_client.signmessage(address, message)
            return signature
            
        except Exception as e:
            logger.error(f"Error signing message: {str(e)}")
            raise ConfigurationError(f"Failed to sign message: {str(e)}")

    def verify_signature(self, address, message, signature):
        """Verify a signature.
        
        Args:
            address (str): The Evrmore address that signed the message
            message (str): The message that was signed
            signature (str): The signature to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        if not EvrmoreAuth.evrmore_available:
            raise ConfigurationError("Evrmore node is not available")
        
        # Try multiple variants since different wallets might handle the message differently
        verification_attempts = []
        
        # Clean the parameters
        clean_address = address.strip()
        clean_signature = signature.strip()
        clean_message = message.strip()
        
        try:
            # 1. Try with the exact message as provided
            logger.info(f"1. Trying exact message: '{clean_message}'")
            result = self.evrmore_client.verifymessage(clean_address, clean_signature, clean_message)
            verification_attempts.append(("exact message", result))
            if result:
                logger.info(f"✅ Signature verified with exact message")
                return True
                
            # 2. Try with just the challenge part (after the prefix)
            prefix = "Sign this message to authenticate with Evrmore: "
            if prefix in clean_message:
                challenge_only = clean_message[len(prefix):].strip()
                logger.info(f"2. Trying with challenge only: '{challenge_only}'")
                result = self.evrmore_client.verifymessage(clean_address, clean_signature, challenge_only)
                verification_attempts.append(("challenge only", result))
                if result:
                    logger.info(f"✅ Signature verified with challenge only")
                    return True
            
            # 3. Try with the address in lowercase
            address_lower = clean_address.lower()
            if clean_address != address_lower:
                logger.info(f"3. Trying with lowercase address: '{address_lower}'")
                result = self.evrmore_client.verifymessage(address_lower, clean_signature, clean_message)
                verification_attempts.append(("lowercase address", result))
                if result:
                    logger.info(f"✅ Signature verified with lowercase address")
                    return True
                    
                # 4. Also try lowercase address with challenge only
                if prefix in clean_message:
                    challenge_only = clean_message[len(prefix):].strip()
                    logger.info(f"4. Trying lowercase address with challenge only: '{challenge_only}'")
                    result = self.evrmore_client.verifymessage(address_lower, clean_signature, challenge_only)
                    verification_attempts.append(("lowercase address + challenge only", result))
                    if result:
                        logger.info(f"✅ Signature verified with lowercase address and challenge only")
                        return True
            
            # Log all verification attempts
            logger.warning(f"❌ All signature verification attempts failed:")
            for attempt_type, result in verification_attempts:
                logger.warning(f"  - {attempt_type}: {result}")
            
            return False
            
        except Exception as e:
            logger.error(f"Error verifying signature: {str(e)}")
            logger.error(f"Address: '{clean_address}'")
            logger.error(f"Message: '{clean_message}'")
            logger.error(f"Signature: '{clean_signature}'")
            return False

    def _create_challenge_text(self, evrmore_address):
        """Create a challenge text for a user.
        
        Args:
            evrmore_address (str): The user's Evrmore address
            
        Returns:
            str: The challenge text
        """
        # Create a unique challenge with timestamp and random component
        timestamp = int(datetime.datetime.utcnow().timestamp())
        random_part = uuid.uuid4().hex[:16]
        
        # Format: "Sign this message to authenticate with Evrmore: {address}:{timestamp}:{random}"
        return f"Sign this message to authenticate with Evrmore: {evrmore_address}:{timestamp}:{random_part}" 