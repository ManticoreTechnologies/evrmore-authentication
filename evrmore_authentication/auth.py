"""Core authentication module for Evrmore Authentication.

This module provides wallet-based authentication using Evrmore signatures.
Users are automatically created on first authentication.
"""

import os
import uuid
import datetime
import secrets
import logging
from typing import Optional, Dict, Any, Union, Tuple, Callable, List
from dataclasses import dataclass, field
import jwt
import traceback

from .crypto import verify_message, generate_key_pair, sign_message as crypto_sign_message
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
DEBUG_MODE = os.getenv("EVRMORE_AUTH_DEBUG", "").lower() in ("true", "1", "yes")

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
    
    def __init__(self, jwt_secret=None, jwt_algorithm=None, debug=None):
        """Initialize authentication system.
        
        Args:
            jwt_secret: Secret for JWT token encryption
            jwt_algorithm: Algorithm for JWT token encryption
            debug: Enable debug mode for detailed logging
        """
        # Ensure jwt_secret is a string
        self.jwt_secret = str(jwt_secret) if jwt_secret is not None else str(JWT_SECRET)
        self.jwt_algorithm = jwt_algorithm or JWT_ALGORITHM
        self.debug = DEBUG_MODE if debug is None else debug
        self._hooks = {
            'pre_challenge': [],
            'post_challenge': [],
            'pre_auth': [],
            'post_auth': [],
            'pre_verify': [],
            'post_verify': []
        }
            
        logger.info("Initialized Evrmore authentication")
        if self.debug:
            logger.info("DEBUG MODE ENABLED - Detailed logging will be shown")

    def add_hook(self, event: str, callback: Callable):
        """Add a hook to be called at a specific event.
        
        Args:
            event: Event name ('pre_challenge', 'post_challenge', 'pre_auth', 'post_auth', 'pre_verify', 'post_verify')
            callback: Function to call
            
        Returns:
            True if hook was added, False otherwise
        """
        if event not in self._hooks:
            logger.warning(f"Unknown hook event: {event}")
            return False
            
        self._hooks[event].append(callback)
        return True
        
    def _run_hooks(self, event: str, **kwargs):
        """Run all hooks registered for an event.
        
        Args:
            event: Event name
            **kwargs: Arguments to pass to hooks
            
        Returns:
            Dictionary of hook results
        """
        results = {}
        
        if event not in self._hooks:
            return results
            
        for i, hook in enumerate(self._hooks[event]):
            try:
                hook_name = getattr(hook, '__name__', f"hook_{i}")
                results[hook_name] = hook(**kwargs)
            except Exception as e:
                logger.error(f"Error in {event} hook {hook}: {str(e)}")
                if self.debug:
                    logger.error(traceback.format_exc())
                
        return results

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
        
        # Run pre-challenge hooks
        hook_results = self._run_hooks('pre_challenge', 
                                      address=original_address, 
                                      expire_minutes=expire_minutes)
        
        if self.debug:
            logger.debug(f"Generating challenge for address: {original_address}")
            logger.debug(f"Pre-challenge hook results: {hook_results}")
        
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
            
            if self.debug:
                logger.debug(f"Created new user with ID: {user.id}")
        elif self.debug:
            logger.debug(f"Found existing user with ID: {user.id}")
        
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
        
        if self.debug:
            logger.debug(f"Created challenge with ID: {challenge.id}")
            logger.debug(f"Challenge expiration: {expires_at}")
        
        # Run post-challenge hooks
        self._run_hooks('post_challenge', 
                       user=user, 
                       challenge=challenge, 
                       challenge_text=challenge_text,
                       expires_at=expires_at)
        
        logger.info(f"Generated challenge for user {user.id}: {challenge_text}")
        return challenge_text

    def authenticate(self, evrmore_address, challenge, signature, 
                    token_expire_minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
                    ip_address=None, user_agent=None, skip_ownership_check=False):
        """Authenticate a user with a signed challenge.
        
        Args:
            evrmore_address: User's Evrmore address
            challenge: Challenge text that was signed
            signature: Signature to verify
            token_expire_minutes: Minutes until token expires
            ip_address: User's IP address (optional)
            user_agent: User's agent string (optional)
            skip_ownership_check: Skip checking if challenge belongs to address
            
        Returns:
            UserSession with token and user details
            
        Raises:
            InvalidSignatureError: Signature verification failed
            ChallengeExpiredError: Challenge has expired
            UserNotFoundError: User not found
        """
        # Clean inputs
        clean_address = evrmore_address.strip()
        clean_challenge = challenge.strip()
        clean_signature = signature.strip()
        
        # Run pre-auth hooks
        hook_results = self._run_hooks('pre_auth', 
                                 evrmore_address=clean_address, 
                                 challenge=clean_challenge,
                                 signature=clean_signature)
                                 
        if self.debug:
            logger.debug(f"Pre-auth hook results: {hook_results}")
        
        # Get user by Evrmore address
        user = User.get_by_address(clean_address)
        if not user:
            user = User.create(clean_address)
            logger.info(f"Created new user with address: {clean_address}")
        
        # Get challenge
        challenge_record = Challenge.get_by_text(clean_challenge)
        if not challenge_record:
            logger.warning(f"Challenge not found: {clean_challenge[:20]}...")
            raise AuthenticationError("Challenge not found")
            
        # Check challenge ownership if required
        if not skip_ownership_check and challenge_record.user_id != user.id:
            logger.warning(f"Challenge does not belong to user {user.id}")
            logger.warning(f"Challenge belongs to user {challenge_record.user_id}")
            raise AuthenticationError("Challenge does not belong to this user")
            
        # Check challenge expiration
        if challenge_record.is_expired:
            logger.warning(f"Challenge has expired at {challenge_record.expires_at}")
            raise ChallengeExpiredError()
            
        # Check if challenge was already used
        if challenge_record.used:
            logger.warning(f"Challenge was already used")
            raise ChallengeAlreadyUsedError()
            
        # Verify signature
        if not self.verify_signature(clean_address, clean_challenge, clean_signature):
            logger.warning(f"❌ Signature verification failed for address: {clean_address}")
            raise InvalidSignatureError(clean_address)
            
        # Mark challenge as used
        challenge_record.used = True
        challenge_record.save()
        
        if self.debug:
            logger.debug(f"Marked challenge as used")
        
        # Generate a token
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expire_minutes)
        token_id = str(uuid.uuid4())
        
        payload = {
            "sub": str(user.id),
            "address": clean_address,
            "jti": token_id,
            "iat": datetime.datetime.utcnow().timestamp(),  # Use timestamp for iat
            "exp": expires_at.timestamp()  # Use timestamp for exp
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        if self.debug:
            logger.debug(f"Generated token with ID: {token_id}")
            logger.debug(f"Token expires at: {expires_at}")
        
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
        
        if self.debug:
            logger.debug(f"Created session with ID: {session.id}")
        
        # Update user's last login time
        user.last_login = datetime.datetime.utcnow()
        user.save()
        
        if self.debug:
            logger.debug(f"Updated user's last login time")
        
        # Create user session
        user_session = UserSession(
            user_id=str(user.id),
            evrmore_address=user.evrmore_address,
            token=token,
            expires_at=expires_at
        )
        
        # Run post-auth hooks
        self._run_hooks('post_auth', 
                       user=user, 
                       session=session,
                       user_session=user_session)
        
        logger.info(f"User {user.id} authenticated successfully")
        return user_session

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

    def verify_signature(self, address, message, signature, run_hooks=True):
        """Verify a signature with multiple strategies.
        
        Args:
            address: Evrmore address that signed the message
            message: Message that was signed
            signature: Signature to verify
            run_hooks: Whether to run hooks
            
        Returns:
            True if signature is valid
        """
        # Clean inputs
        clean_address = address.strip()
        clean_message = message.strip()
        clean_signature = signature.strip()
        
        if self.debug:
            logger.debug(f"Verifying signature for address: {clean_address}")
            logger.debug(f"Message: {clean_message}")
            logger.debug(f"Signature length: {len(clean_signature)}")
        
        if run_hooks:
            # Run pre-verify hooks
            hook_results = self._run_hooks('pre_verify', 
                                         address=clean_address, 
                                         message=clean_message,
                                         signature=clean_signature)
                                         
            if self.debug:
                logger.debug(f"Pre-verify hook results: {hook_results}")
                
            # Check if any hook returned a definitive result
            for result in hook_results.values():
                if result is True or result is False:
                    logger.info(f"Using hook verification result: {result}")
                    return result
        
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
                if self.debug:
                    logger.debug(f"Attempt {i}: Verifying with address: '{test_address}', message: '{test_message}'")
                
                result = verify_message(test_address, clean_signature, test_message)
                logger.info(f"Attempt {i} result: {result}")
                
                if result:
                    logger.info(f"✅ Signature verification successful with method {i}")
                    
                    if run_hooks:
                        # Run post-verify hooks
                        self._run_hooks('post_verify', 
                                       address=clean_address, 
                                       message=clean_message,
                                       signature=clean_signature,
                                       result=True,
                                       method=i)
                    
                    return True
            except Exception as e:
                logger.warning(f"Verification attempt {i} failed with error: {str(e)}")
                if self.debug:
                    logger.debug(traceback.format_exc())
        
        logger.error("❌ All signature verification methods failed")
        
        if run_hooks:
            # Run post-verify hooks with failure
            self._run_hooks('post_verify', 
                           address=clean_address, 
                           message=clean_message,
                           signature=clean_signature,
                           result=False,
                           method=None)
            
        return False

    def verify_signature_only(self, address, message, signature):
        """Verify a signature without any challenge lookups or database checks.
        
        This is useful for external verification or custom authentication flows.
        
        Args:
            address: Evrmore address that signed the message
            message: Message that was signed
            signature: Signature to verify
            
        Returns:
            True if signature is valid
        """
        return self.verify_signature(address, message, signature, run_hooks=False)

    def get_challenge_details(self, challenge_text):
        """Get details about a challenge.
        
        Args:
            challenge_text: The challenge text
            
        Returns:
            Dictionary with challenge details, or None if not found
        """
        challenge = Challenge.get_by_text(challenge_text)
        if not challenge:
            return None
            
        return {
            "id": challenge.id,
            "user_id": challenge.user_id,
            "expires_at": challenge.expires_at,
            "is_expired": challenge.is_expired,
            "used": challenge.used,
            "created_at": challenge.created_at
        }

    def reassign_challenge(self, challenge_text, new_user_id=None, new_address=None):
        """Reassign a challenge to a different user.
        
        This is useful for handling challenge migration or fixing ownership issues.
        
        Args:
            challenge_text: The challenge text
            new_user_id: ID of the user to assign the challenge to
            new_address: Evrmore address to find or create a user for
            
        Returns:
            True if successful
            
        Raises:
            AuthenticationError: If challenge not found
            UserNotFoundError: If user not found
        """
        challenge = Challenge.get_by_text(challenge_text)
        if not challenge:
            raise AuthenticationError(f"Challenge not found: {challenge_text}")
            
        if new_address:
            # Find or create user by address
            user = User.get_by_address(new_address)
            if not user:
                # Create a new user
                user = User(
                    id=str(uuid.uuid4()),
                    evrmore_address=new_address
                )
                user.save()
                logger.info(f"Created new user with address: {new_address}")
            new_user_id = user.id
                
        if not new_user_id:
            raise UserNotFoundError("No user ID or address provided")
            
        # Verify user exists
        user = User.get_by_id(new_user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {new_user_id} not found")
            
        # Update challenge
        old_user_id = challenge.user_id
        challenge.user_id = new_user_id
        challenge.save()
        
        logger.info(f"Reassigned challenge {challenge.id} from user {old_user_id} to {new_user_id}")
        return True

    def create_manual_challenge(self, evrmore_address, challenge_text=None, expire_minutes=CHALLENGE_EXPIRE_MINUTES):
        """Create a manual challenge for a user.
        
        Args:
            evrmore_address: User's Evrmore address
            challenge_text: Custom challenge text (optional)
            expire_minutes: Minutes until challenge expires
                
        Returns:
            Challenge text
        """
        # Get or create user
        user = User.get_by_address(evrmore_address)
        if not user:
            # Create a new user
            user = User(
                id=str(uuid.uuid4()),
                evrmore_address=evrmore_address
            )
            user.save()
            logger.info(f"Created new user with address: {evrmore_address}")
            
        # Generate or use provided challenge text
        if not challenge_text:
            challenge_text = self._create_challenge_text(evrmore_address)
            
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
        
        logger.info(f"Created manual challenge for user {user.id}: {challenge_text}")
        return challenge_text
        
    def cleanup_expired_challenges(self):
        """Clean up expired challenges.
        
        Returns:
            Number of challenges removed
        """
        from .models import cleanup_expired_challenges
        return cleanup_expired_challenges()
        
    def cleanup_expired_sessions(self):
        """Clean up expired sessions.
        
        Returns:
            Number of sessions removed
        """
        from .models import cleanup_expired_sessions
        return cleanup_expired_sessions()

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
        return crypto_sign_message(message, wif_key) 