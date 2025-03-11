"""Core authentication module for Evrmore Authentication.

This module provides wallet-based authentication using Evrmore signatures.
Users are automatically created on first authentication.
"""

import os
import uuid
import datetime
import secrets
import logging
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
import jwt
from evrmore_rpc import EvrmoreClient

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

# Environment configuration with defaults
EVRMORE_RPC_HOST = os.getenv("EVRMORE_RPC_HOST", "localhost")
EVRMORE_RPC_PORT = int(os.getenv("EVRMORE_RPC_PORT", "8819"))
EVRMORE_RPC_USER = os.getenv("EVRMORE_RPC_USER", "")
EVRMORE_RPC_PASSWORD = os.getenv("EVRMORE_RPC_PASSWORD", "")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
CHALLENGE_EXPIRE_MINUTES = int(os.getenv("CHALLENGE_EXPIRE_MINUTES", "10"))

if not JWT_SECRET:
    logger.warning("JWT_SECRET not set in environment. Using a generated value for this session.")

@dataclass
class UserSession:
    """User's authenticated session information."""
    user_id: str
    evrmore_address: str
    token: str
    expires_at: datetime.datetime


class EvrmoreAuth:
    """Evrmore wallet-based authentication handling.
    
    This class provides methods for authenticating users with Evrmore wallet signatures.
    Users are automatically created on first authentication.
    """
    
    # Class attribute to track Evrmore node availability
    evrmore_available = False
    
    def __init__(self, evrmore_client=None, db=None):
        """Initialize authentication system.
        
        Args:
            evrmore_client: Optional EvrmoreClient instance
            db: Optional database client instance
        """
        self.db = db
        self.jwt_secret = JWT_SECRET
            
        # Set up Evrmore RPC client
        try:
            self.evrmore_client = evrmore_client or EvrmoreClient()
            # Test connection
            self.evrmore_client.getblockchaininfo()
            logger.info("Successfully connected to Evrmore node")
            EvrmoreAuth.evrmore_available = True
        except Exception as e:
            logger.error(f"Failed to initialize Evrmore RPC: {str(e)}")
            EvrmoreAuth.evrmore_available = False
            self.evrmore_client = None
            raise ConfigurationError(f"Evrmore RPC initialization failed: {str(e)}")
    
    def _get_db(self):
        """Get database connection."""
        if self.db is not None:
            return self.db
        
        from .db import get_db
        return get_db()

    def generate_challenge(self, evrmore_address, expire_minutes=CHALLENGE_EXPIRE_MINUTES):
        """Generate a challenge for a user to sign.
        
        Args:
            evrmore_address: User's Evrmore address
            expire_minutes: Minutes until challenge expires
                
        Returns:
            Challenge text to be signed
        """
        from .db import create_user, create_challenge, get_user_by_address
        
        # Keep original address format for signing
        original_address = evrmore_address.strip()
        
        # Get or create user (using original case)
        user_data = get_user_by_address(original_address)
        if not user_data:
            user_data = create_user(original_address)
        
        # Generate challenge with expiration, using original address
        challenge_text = self._create_challenge_text(original_address)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
        
        # Store challenge
        create_challenge(
            user_id=user_data["id"],
            challenge_text=challenge_text,
            expires_at=expires_at
        )
        
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
        
        Automatically creates users if they don't exist.
        
        Args:
            evrmore_address: User's Evrmore address
            challenge: Challenge text that was signed
            signature: Signature from wallet
            ip_address: Optional client IP
            user_agent: Optional client user agent
            token_expire_minutes: Minutes until token expires
                
        Returns:
            UserSession with authentication token
        """
        from .db import (
            get_user_by_address, 
            create_user,
            get_challenge_by_text, 
            mark_challenge_used,
            create_session,
            update_user,
            get_user_by_id
        )
        
        # Preserve original address format
        original_address = evrmore_address.strip()
        
        # Get challenge first to avoid race conditions
        challenge_data = get_challenge_by_text(challenge)
        if not challenge_data:
            raise ChallengeExpiredError()
        
        # Check if challenge has expired
        challenge_obj = Challenge.from_dict(challenge_data)
        if challenge_obj.is_expired:
            raise ChallengeExpiredError(challenge_obj.id)
        
        # Check if challenge has already been used
        if challenge_data["used"]:
            raise ChallengeAlreadyUsedError(challenge_obj.id)
        
        # Get user from challenge's user_id to ensure we're using the same user 
        # that was created during challenge generation
        user_data = get_user_by_id(challenge_data["user_id"])
        
        # If user doesn't exist (which should be rare), recreate it
        if not user_data:
            # This is an unusual case but we'll handle it
            logger.warning(f"User not found for challenge {challenge_obj.id}, recreating user")
            user_data = create_user(original_address)
        
        # Verify signature
        if not self.verify_signature(original_address, challenge, signature):
            logger.warning(f"Invalid signature for {original_address}")
            raise InvalidSignatureError(original_address)
        
        # Mark challenge used
        mark_challenge_used(challenge_data["id"])
        
        # Create session token
        token_expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expire_minutes)
        user_id = str(user_data["id"])
        
        payload = {
            "sub": user_id,
            "addr": original_address,
            "exp": int(token_expires.timestamp()),
            "iat": int(datetime.datetime.utcnow().timestamp()),
            "jti": str(uuid.uuid4())
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=JWT_ALGORITHM)
        
        # Record session and update user
        create_session(
            user_id=user_id,
            token=token,
            expires_at=token_expires,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        update_user(user_id, last_login=datetime.datetime.utcnow())
        
        return UserSession(
            user_id=user_id,
            evrmore_address=original_address,
            token=token,
            expires_at=token_expires
        )

    def validate_token(self, token):
        """Validate a JWT token.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Decoded token payload if valid
        """
        from .db import get_session_by_token
        
        try:
            # Decode and validate token
            # Note: We ignore the "iat" (issued at) validation to avoid timezone/clock issues
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[JWT_ALGORITHM],
                options={"verify_iat": False}  # Skip "issued at" verification
            )
            
            # Check if token is still active
            session_data = get_session_by_token(token)
            if not session_data or not session_data["is_active"]:
                raise InvalidTokenError("Token has been invalidated")
            
            return payload
            
        except jwt.PyJWTError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            raise InvalidTokenError(f"Token validation failed: {str(e)}")

    def get_user_by_token(self, token):
        """Get user from token.
        
        Args:
            token: JWT token
            
        Returns:
            User object if token is valid
        """
        from .db import get_user_by_id
        
        payload = self.validate_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise InvalidTokenError("Token does not contain user ID")
        
        user_data = get_user_by_id(user_id)
        if not user_data:
            raise UserNotFoundError(user_id)
        
        return User.from_dict(user_data)

    def invalidate_token(self, token):
        """Invalidate a token (logout).
        
        Args:
            token: JWT token to invalidate
            
        Returns:
            True if successful
        """
        from .db import get_session_by_token, invalidate_session
        
        try:
            session_data = get_session_by_token(token)
            if not session_data:
                logger.warning(f"Token not found: {token[:10]}...")
                return False
            
            invalidate_session(session_data["id"])
            return True
            
        except Exception as e:
            logger.error(f"Error invalidating token: {str(e)}")
            return False

    def invalidate_all_tokens(self, user_id):
        """Invalidate all tokens for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
        """
        from .db import invalidate_all_sessions
        
        try:
            user_id = str(user_id)
            count = invalidate_all_sessions(user_id)
            logger.info(f"Invalidated {count} tokens for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error invalidating all tokens: {str(e)}")
            return False

    def verify_signature(self, address, message, signature):
        """Verify a signature with multiple strategies.
        
        Args:
            address: Evrmore address that signed the message
            message: Message that was signed
            signature: Signature to verify
            
        Returns:
            True if signature is valid
        """
        if not EvrmoreAuth.evrmore_available:
            raise ConfigurationError("Evrmore node is not available")
        
        # Clean inputs
        clean_address = address.strip()
        clean_message = message.strip()
        clean_signature = signature.strip()
        
        logger.info(f"Verifying signature for address: {clean_address}")
        logger.info(f"Message: {clean_message}")
        logger.info(f"Signature: {clean_signature}")
        
        # Try verification with different formats
        verification_attempts = [
            # 1. Exact message with original address (most common case)
            (clean_address, clean_message),
            
            # 2. Challenge part only with original address
            (clean_address, clean_message.replace("Sign this message to authenticate with Evrmore: ", "")),
        ]
        
        # Try each verification approach
        for i, (test_address, test_message) in enumerate(verification_attempts, 1):
            try:
                logger.info(f"Attempt {i}: Verifying with address: '{test_address}', message: '{test_message}'")
                result = self.evrmore_client.verifymessage(test_address, clean_signature, test_message)
                logger.info(f"Attempt {i} result: {result}")
                if result:
                    logger.info(f"✅ Signature verification successful with method {i}")
                    return True
            except Exception as e:
                logger.warning(f"Verification attempt {i} failed with error: {str(e)}")
                # Try diagnostics with a known good address if the issue is "Invalid address"
                if "Invalid address" in str(e) and i == 1:
                    try:
                        # Try to get a valid address for testing
                        test_addr = self.evrmore_client.getnewaddress()
                        logger.info(f"Testing with a known good address: {test_addr}")
                        # Just do a query to see if RPC is working
                        self.evrmore_client.validateaddress(test_addr)
                        logger.info("RPC connection is working with valid addresses")
                    except Exception as test_err:
                        logger.error(f"Error during address test: {str(test_err)}")
        
        logger.warning("❌ All signature verification attempts failed")
        return False

    def _create_challenge_text(self, evrmore_address):
        """Create a challenge text.
        
        Args:
            evrmore_address: User's Evrmore address
            
        Returns:
            Challenge text
        """
        timestamp = int(datetime.datetime.utcnow().timestamp())
        random_part = uuid.uuid4().hex[:16]
        
        return f"Sign this message to authenticate with Evrmore: {evrmore_address}:{timestamp}:{random_part}" 