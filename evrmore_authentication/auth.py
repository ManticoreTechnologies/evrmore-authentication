"""Core authentication module for Evrmore Authentication.

This module provides wallet-based authentication using Evrmore signatures.
Users are automatically created on first authentication.
"""

import os
import uuid
import datetime
import secrets
import logging
from typing import Optional, Dict, Any, Union, Tuple
from dataclasses import dataclass
import jwt

from .crypto import verify_message, generate_key_pair
from .models import User, Challenge, Session
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
    evrmore_available = True
    
    def __init__(self, jwt_secret=None, jwt_algorithm=None):
        """Initialize authentication system.
        
        Args:
            jwt_secret: Secret for JWT token encryption
            jwt_algorithm: Algorithm for JWT token encryption
        """
        self.jwt_secret = jwt_secret or JWT_SECRET
        self.jwt_algorithm = jwt_algorithm or JWT_ALGORITHM
            
        logger.info("Initialized Evrmore authentication")

    def generate_challenge(self, evrmore_address, expire_minutes=CHALLENGE_EXPIRE_MINUTES):
        """Generate a challenge for a user to sign.
        
        Args:
            evrmore_address: User's Evrmore address
            expire_minutes: Minutes until challenge expires
                
        Returns:
            Challenge text to be signed
        """
        # Keep original address format for signing
        original_address = evrmore_address.strip()
        
        # Get or create user (using original case)
        user = User.get_by_address(original_address)
        if not user:
            # Create a new user
            user = User(
                id=str(uuid.uuid4()),
                evrmore_address=original_address
            )
            user.save()
            logger.info(f"Created new user with address: {original_address}")
        
        # Generate a challenge
        challenge_text = self._create_challenge_text(original_address)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
        
        # Create challenge in database
        challenge = Challenge(
            id=str(uuid.uuid4()),
            user_id=user.id,
            challenge_text=challenge_text,
            expires_at=expires_at,
            used=False
        )
        challenge.save()
        
        logger.info(f"Generated challenge for user {user.id}: {challenge_text}")
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
        """Authenticate a user with their signed challenge.
        
        Args:
            evrmore_address: The Evrmore address that signed the challenge
            challenge: The challenge text that was signed
            signature: The signature created by signing the challenge
            ip_address: User's IP address (optional)
            user_agent: User's agent string (optional)
            token_expire_minutes: Minutes until token expires (optional)
            
        Returns:
            UserSession with token and user information
            
        Raises:
            UserNotFoundError: If user with the address is not found
            ChallengeExpiredError: If the challenge has expired
            ChallengeAlreadyUsedError: If the challenge has already been used
            InvalidSignatureError: If signature verification fails
        """
        clean_address = evrmore_address.strip()
        clean_challenge = challenge.strip()
        clean_signature = signature.strip()
        
        # Find user by address
        user = User.get_by_address(clean_address)
        if not user:
            raise UserNotFoundError(f"User with address {clean_address} not found")
        
        # Find challenge record
        challenge_record = Challenge.get_by_text(clean_challenge)
        if not challenge_record:
            raise AuthenticationError(f"Challenge not found: {clean_challenge}")
        
        # Check if challenge belongs to the user
        if challenge_record.user_id != user.id:
            logger.warning(f"Challenge belongs to different user")
            raise AuthenticationError("Challenge does not belong to this user")
            
        # Check if challenge has been used
        if challenge_record.used:
            raise ChallengeAlreadyUsedError("This challenge has already been used")
            
        # Check if challenge has expired
        if challenge_record.is_expired:
            raise ChallengeExpiredError(f"Challenge expired at {challenge_record.expires_at}")
            
        # Verify signature
        if not self.verify_signature(clean_address, clean_challenge, clean_signature):
            raise InvalidSignatureError("Invalid signature")
            
        # Mark challenge as used
        challenge_record.used = True
        challenge_record.save()
        
        # Generate a token
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expire_minutes)
        token_id = str(uuid.uuid4())
        
        payload = {
            "sub": str(user.id),
            "address": clean_address,
            "jti": token_id,
            "iat": datetime.datetime.utcnow(),
            "exp": expires_at
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Record session and update user
        session = Session(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token=token,
            created_at=datetime.datetime.utcnow(),
            expires_at=expires_at,
            is_active=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        session.save()
        
        # Update user's last login time
        user.last_login = datetime.datetime.utcnow()
        user.save()
        
        return UserSession(
            user_id=str(user.id),
            evrmore_address=user.evrmore_address,
            token=token,
            expires_at=expires_at
        )

    def validate_token(self, token):
        """Validate a JWT token.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Decoded token payload if valid
        """
        try:
            # Decode and validate token
            # Note: We ignore the "iat" (issued at) validation to avoid timezone/clock issues
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[self.jwt_algorithm],
                options={"verify_iat": False}  # Skip "issued at" verification
            )
            
            # Check if token is still active
            session = Session.get_by_token(token)
            if not session or not session.is_active:
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
        payload = self.validate_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise InvalidTokenError("Token does not contain user ID")
        
        user = User.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(user_id)
        
        return user

    def get_user_by_id(self, user_id):
        """Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object if found
        """
        user = User.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(user_id)
        
        return user

    def invalidate_token(self, token):
        """Invalidate a token (logout).
        
        Args:
            token: JWT token to invalidate
            
        Returns:
            True if successful
        """
        try:
            session = Session.get_by_token(token)
            if not session:
                logger.warning(f"Token not found: {token[:10]}...")
                return False
            
            session.is_active = False
            session.save()
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
        try:
            user_id = str(user_id)
            sessions = Session.get_by_user_id(user_id)
            count = 0
            
            for session in sessions:
                if session.is_active:
                    session.is_active = False
                    session.save()
                    count += 1
                    
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
        # Clean inputs
        clean_address = address.strip()
        clean_message = message.strip()
        clean_signature = signature.strip()
        
        logger.info(f"Verifying signature for address: {clean_address}")
        logger.info(f"Message: {clean_message}")
        
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
                result = verify_message(test_address, clean_signature, test_message)
                logger.info(f"Attempt {i} result: {result}")
                if result:
                    logger.info(f"✅ Signature verification successful with method {i}")
                    return True
            except Exception as e:
                logger.warning(f"Verification attempt {i} failed with error: {str(e)}")
        
        logger.error("❌ All signature verification methods failed")
        return False

    def _create_challenge_text(self, evrmore_address):
        """Create a unique challenge text for an address.
        
        Args:
            evrmore_address: User's Evrmore address
            
        Returns:
            Challenge text
        """
        # Create a unique, timestamped challenge
        timestamp = int(datetime.datetime.utcnow().timestamp())
        unique_id = secrets.token_hex(8)
        return f"Sign this message to authenticate with Evrmore: {evrmore_address}:{timestamp}:{unique_id}"

    def create_wallet_address(self):
        """Create a new Evrmore wallet address for testing.
        
        Returns:
            A new Evrmore address
        """
        wif_key, address = generate_key_pair()
        logger.info(f"Generated new test address: {address}")
        return address, wif_key
        
    def sign_message(self, wif_key, message):
        """Sign a message with an Evrmore private key.
        
        Args:
            wif_key: The WIF-encoded private key
            message: The message to sign
            
        Returns:
            Base64-encoded signature
        """
        from .crypto import sign_message as crypto_sign_message
        return crypto_sign_message(message, wif_key) 