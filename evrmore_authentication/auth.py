"""Core authentication module for Evrmore Authentication.

This module provides wallet-based authentication using Evrmore signatures.
Users are automatically created on first authentication.
"""

import os
import sys
import time
import uuid
import secrets
import logging
import hashlib
from typing import Optional, Dict, Any, Union, Tuple, Callable, List
from dataclasses import dataclass, field
import jwt
import traceback
from pathlib import Path
import datetime

from .crypto import verify_message, generate_key_pair, sign_message as crypto_sign_message, pubkey_to_address, wif_to_privkey
from .models import User, Challenge, Session, OAuthClient, OAuthAuthorizationCode, OAuthToken
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
JWT_PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", "")
JWT_PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "")
JWT_ISSUER = os.getenv("EVR_AUTH_JWT_ISSUER", "evrmore-authentication")
JWT_AUDIENCE = os.getenv("EVR_AUTH_JWT_AUDIENCE", "evrmore-api")
JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("EVR_AUTH_JWT_ACCESS_TOKEN_EXPIRES", "3600"))  # 1 hour
JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv("EVR_AUTH_JWT_REFRESH_TOKEN_EXPIRES", "2592000"))  # 30 days
CHALLENGE_EXPIRE_MINUTES = int(os.getenv("CHALLENGE_EXPIRE_MINUTES", "10"))
DEBUG_MODE = os.getenv("EVRMORE_AUTH_DEBUG", "").lower() in ("true", "1", "yes")

if not JWT_SECRET and JWT_ALGORITHM == "HS256":
    logger.warning("JWT_SECRET not set in environment. Using a generated value for this session.")
    
if JWT_ALGORITHM == "RS256" and (not JWT_PRIVATE_KEY_PATH or not JWT_PUBLIC_KEY_PATH):
    logger.warning("RS256 algorithm selected but JWT_PRIVATE_KEY_PATH or JWT_PUBLIC_KEY_PATH not set")

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
    
    def __init__(self, 
                 jwt_secret: str = JWT_SECRET,
                 jwt_algorithm: str = JWT_ALGORITHM,
                 jwt_private_key_path: str = JWT_PRIVATE_KEY_PATH,
                 jwt_public_key_path: str = JWT_PUBLIC_KEY_PATH,
                 jwt_issuer: str = JWT_ISSUER,
                 jwt_audience: str = JWT_AUDIENCE,
                 access_token_expires: int = JWT_ACCESS_TOKEN_EXPIRES,
                 refresh_token_expires: int = JWT_REFRESH_TOKEN_EXPIRES,
                 debug: bool = DEBUG_MODE):
        """Initialize authentication system.
        
        Args:
            jwt_secret: Secret for JWT token encryption (for HS256)
            jwt_algorithm: Algorithm for JWT token encryption (HS256 or RS256)
            debug: Enable debug mode for detailed logging
            jwt_private_key_path: Path to private key file (for RS256)
            jwt_public_key_path: Path to public key file (for RS256)
            jwt_issuer: JWT issuer
            jwt_audience: JWT audience
            access_token_expires: Access token expiration time in seconds
            refresh_token_expires: Refresh token expiration time in seconds
        """
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_issuer = jwt_issuer
        self.jwt_audience = jwt_audience
        self.access_token_expires = access_token_expires
        self.refresh_token_expires = refresh_token_expires
        self.debug = debug
        
        # Load RSA keys if using RS256
        self.private_key = None
        self.public_key = None
        if jwt_algorithm.startswith('RS'):
            self.private_key, self.public_key = self._load_rsa_keys(
                jwt_private_key_path, 
                jwt_public_key_path
            )
        
        self._hooks = {
            'pre_challenge': [],
            'post_challenge': [],
            'pre_auth': [],
            'post_auth': [],
            'pre_verify': [],
            'post_verify': [],
            'pre_oauth_authorize': [],
            'post_oauth_authorize': [],
            'pre_oauth_token': [],
            'post_oauth_token': []
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
                    ip_address=None, user_agent=None, skip_ownership_check=False,
                    scope="profile"):
        """Authenticate a user with a challenge and signature.
        
        Args:
            evrmore_address: User's Evrmore address
            challenge: Challenge text that was signed
            signature: Signature produced by wallet
            token_expire_minutes: Minutes until token expires (default: 60)
            ip_address: User's IP address for session tracking
            user_agent: User's browser/client info for session tracking
            skip_ownership_check: Whether to skip the ownership check
            scope: OAuth 2.0 scope
            
        Returns:
            Session with token if authentication successful
            
        Raises:
            AuthenticationError: If authentication fails
        """
        if not challenge or not signature:
            raise AuthenticationError("Challenge and signature required")
        
        # Keep original address format for validation
        original_address = evrmore_address.strip()
        
        # Run pre-authentication hooks
        hook_results = self._run_hooks('pre_authenticate', 
                                      address=original_address, 
                                      challenge=challenge, 
                                      signature=signature)
        
        if self.debug:
            logger.debug(f"Authenticating address: {original_address}")
            logger.debug(f"With challenge: {challenge}")
            logger.debug(f"Pre-authentication hook results: {hook_results}")
        
        # Verify challenge format
        challenge_data = self.get_challenge_details(challenge)
        if not challenge_data:
            raise AuthenticationError("Invalid challenge format")
        
        # Find the challenge in database
        db_challenge = Challenge.get_by_text(challenge)
        if not db_challenge:
            raise AuthenticationError("Challenge not found")
        
        # Check if challenge is expired
        if db_challenge.is_expired:
            raise ChallengeExpiredError(db_challenge.id)
        
        # Check if challenge has been used
        if db_challenge.used:
            raise ChallengeAlreadyUsedError(db_challenge.id)
        
        # Verify signature
        if not skip_ownership_check:
            if not self.verify_signature(original_address, challenge, signature):
                raise SignatureVerificationError()
        
        # Get user
        user = User.get_by_address(original_address)
        if not user:
            raise UserNotFoundError(f"User with address {original_address} not found")
        
        # Mark challenge as used
        db_challenge.used = True
        db_challenge.save()
        
        # Update user's last login
        user.last_login = datetime.datetime.utcnow()
        user.save()
        
        # Create a token
        # Use a default value if token_expire_minutes is None
        if token_expire_minutes is None:
            token_expire_minutes = JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        
        token = self._generate_jwt_token(
            user_id=user.id, 
            evrmore_address=user.evrmore_address,
            expiration=token_expire_minutes,
            scope=scope
        )
        
        # Create a session
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expire_minutes)
        session = Session(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token=token,
            expires_at=expires_at,
            is_active=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        session.save()
        
        if self.debug:
            logger.debug(f"Created session {session.id} for user {user.id}")
        
        # Run post-authentication hooks
        self._run_hooks('post_authenticate', 
                       address=original_address, 
                       user=user, 
                       session=session)
        
        # Create a user session object
        user_session = UserSession(
            user_id=user.id,
            evrmore_address=user.evrmore_address,
            token=token,
            expires_at=expires_at
        )
        
        return user_session

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate a JWT token.
        
        Args:
            token: JWT token
            
        Returns:
            Dict[str, Any]: Token payload if valid, None otherwise
        """
        if not token:
            return None
            
        try:
            # Determine key based on algorithm
            key = None
            if self.jwt_algorithm.startswith('RS'):
                key = self.public_key
                if not key:
                    logger.error("Public key not available for RS256 verification")
                    return None
            else:
                key = self.jwt_secret
                
            # Decode and validate the token
            payload = jwt.decode(
                token,
                key,
                algorithms=[self.jwt_algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "sub", "jti"],
                    "verify_aud": False  # Skip audience validation
                }
            )
            
            # Debug log
            if self.debug:
                logger.debug(f"Token validated: {payload}")
                
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error validating token: {str(e)}")
            return None

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

    def verify_signature_only(self, evrmore_address: str, message: str, signature: str) -> bool:
        """Verify a signature without creating a challenge or user.
        
        This is useful for simple verification without the full challenge flow.
        
        Args:
            evrmore_address: Evrmore address
            message: Message that was signed
            signature: Signature of the message
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Check signature using crypto utils
            # The verify_message function expects (address, signature, message)
            result = verify_message(evrmore_address, signature, message)
            
            if self.debug:
                if result:
                    logger.debug(f"Signature verified for address {evrmore_address}")
                else:
                    logger.debug(f"Signature verification failed for address {evrmore_address}")
                    
            return result
        except Exception as e:
            logger.error(f"Error verifying signature: {str(e)}")
            return False

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

    # OAuth 2.0 methods
    
    def register_oauth_client(self, client_name: str, redirect_uris: List[str], 
                            client_uri: str = None, 
                            allowed_response_types: List[str] = None,
                            allowed_scopes: List[str] = None,
                            created_by: str = None) -> 'OAuthClient':
        """Register a new OAuth 2.0 client.
        
        Args:
            client_name: Name of the client application
            redirect_uris: List of allowed redirect URIs
            client_uri: URI of the client application
            allowed_response_types: List of allowed response types (default: ["code"])
            allowed_scopes: List of allowed scopes (default: ["profile"])
            created_by: ID of the user who created the client
            
        Returns:
            OAuthClient: Created client
        """
        from .models import OAuthClient
        
        # Validate input
        if not client_name:
            raise ValueError("client_name is required")
            
        if not redirect_uris:
            raise ValueError("At least one redirect_uri is required")
            
        # Validate redirect URIs
        for uri in redirect_uris:
            if not uri.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid redirect_uri: {uri} (must be http or https)")
                
        # Create client
        client = OAuthClient(
            client_name=client_name,
            redirect_uris=redirect_uris,
            client_uri=client_uri,
            allowed_response_types=allowed_response_types,
            allowed_scopes=allowed_scopes,
            created_by=created_by
        )
        
        # Save to database
        if not client.save():
            raise Exception("Failed to save OAuth client")
            
        # Trigger hooks
        self._run_hooks('on_oauth_client_registered', client=client)
            
        if self.debug:
            logger.debug(f"Registered OAuth client: {client.client_name} (ID: {client.client_id})")
            
        return client
    
    def create_authorization_code(self, client_id: str, user_id: str, 
                                redirect_uri: str, scope: str = "profile") -> 'OAuthAuthorizationCode':
        """Create an OAuth 2.0 authorization code.
        
        Args:
            client_id: OAuth client ID
            user_id: User ID
            redirect_uri: Redirect URI
            scope: OAuth scope
            
        Returns:
            OAuthAuthorizationCode: Created authorization code
        """
        from .models import OAuthAuthorizationCode, OAuthClient
        
        # Verify client exists
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            raise ValueError(f"Invalid client_id: {client_id}")
            
        # Verify client can use the provided redirect URI
        if not client.verify_redirect_uri(redirect_uri):
            raise ValueError(f"Invalid redirect_uri: {redirect_uri}")
            
        # Verify client can use the provided scope
        if not client.verify_scope(scope):
            raise ValueError(f"Invalid scope: {scope}")
            
        # Create authorization code
        auth_code = OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code=secrets.token_urlsafe(32),
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        )
        
        # Save to database
        if not auth_code.save():
            raise Exception("Failed to save authorization code")
            
        # Trigger hooks
        self._run_hooks('on_authorization_code_created', 
                       auth_code=auth_code,
                       client_id=client_id,
                       user_id=user_id,
                       redirect_uri=redirect_uri,
                       scope=scope)
            
        if self.debug:
            logger.debug(f"Created authorization code for client {client_id}, user {user_id}")
            
        return auth_code
    
    def exchange_code_for_token(self, code: str, client_id: str, client_secret: str, 
                              redirect_uri: str) -> 'OAuthToken':
        """Exchange an authorization code for an access token.
        
        Args:
            code: Authorization code
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: Redirect URI
            
        Returns:
            OAuthToken: Created token
            
        Raises:
            ValueError: If code is invalid or expired
            AuthenticationError: If client authentication fails
        """
        from .models import OAuthAuthorizationCode, OAuthClient, OAuthToken, User
        from .exceptions import AuthenticationError
        
        # Debug logging
        logger.info(f"Exchanging code for token: code={code}, client_id={client_id}, redirect_uri={redirect_uri}")
        
        # Verify client
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            logger.error(f"Invalid client_id: {client_id}")
            raise AuthenticationError(f"Invalid client_id: {client_id}")
            
        logger.info(f"Client verified: {client.client_name}")
            
        # Verify client secret
        if not client.verify_client_secret(client_secret):
            logger.error("Invalid client_secret")
            raise AuthenticationError("Invalid client_secret")
            
        logger.info("Client secret verified")
            
        # Get authorization code
        auth_code = OAuthAuthorizationCode.get_by_code(code)
        if not auth_code:
            logger.error(f"Invalid code: {code}")
            raise ValueError(f"Invalid code: {code}")
            
        logger.info(f"Authorization code found: {auth_code.id}, user_id={auth_code.user_id}")
            
        # Verify code is valid for this client
        if not auth_code.is_valid(client_id, redirect_uri):
            logger.error(f"Invalid code, client_id, or redirect_uri. Code client_id: {auth_code.client_id}, provided client_id: {client_id}, code redirect_uri: {auth_code.redirect_uri}, provided redirect_uri: {redirect_uri}")
            raise ValueError("Invalid code, client_id, or redirect_uri")
            
        logger.info("Authorization code is valid")
            
        # Get user
        user = User.get_by_id(auth_code.user_id)
        if not user:
            logger.error(f"User not found: {auth_code.user_id}")
            raise ValueError(f"User not found: {auth_code.user_id}")
            
        logger.info(f"User found: {user.id}, address={user.evrmore_address}")
            
        # Mark code as used
        auth_code.use()
        logger.info("Authorization code marked as used")
        
        # Create tokens
        access_token = self._generate_jwt_token(
            user_id=user.id,
            evrmore_address=user.evrmore_address,
            token_type="access",
            scope=auth_code.scope,
            client_id=client_id
        )
        
        refresh_token = self._generate_jwt_token(
            user_id=user.id,
            evrmore_address=user.evrmore_address,
            token_type="refresh",
            scope=auth_code.scope,
            client_id=client_id
        )
        
        # Calculate expiration times
        access_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.access_token_expires)
        refresh_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.refresh_token_expires)
        
        # Create token object
        token = OAuthToken(
            id=str(uuid.uuid4()),
            access_token=access_token,
            refresh_token=refresh_token,
            client_id=client_id,
            user_id=user.id,
            scope=auth_code.scope,
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at
        )
        
        # Save to database
        if not token.save():
            raise Exception("Failed to save OAuth token")
            
        # Trigger hooks
        self._run_hooks('on_token_created', 
                       token=token,
                       client_id=client_id,
                       user_id=auth_code.user_id,
                       scope=auth_code.scope)
            
        if self.debug:
            logger.debug(f"Created token for user {user.id} and client {client_id}")
            
        return token
    
    def refresh_token(self, refresh_token: str, client_id: str, client_secret: str) -> 'OAuthToken':
        """Refresh an OAuth 2.0 token.
        
        Args:
            refresh_token: Refresh token
            client_id: OAuth client ID
            client_secret: OAuth client secret
            
        Returns:
            OAuthToken: New token
            
        Raises:
            ValueError: If refresh token is invalid or expired
            AuthenticationError: If client authentication fails
        """
        from .models import OAuthClient, OAuthToken, User
        from .exceptions import AuthenticationError
        
        # Verify client
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            raise AuthenticationError(f"Invalid client_id: {client_id}")
            
        # Verify client secret
        if not client.verify_client_secret(client_secret):
            raise AuthenticationError("Invalid client_secret")
            
        # Get token
        old_token = OAuthToken.get_by_refresh_token(refresh_token)
        if not old_token:
            raise ValueError(f"Invalid refresh_token")
            
        # Verify token belongs to this client
        if old_token.client_id != client_id:
            raise AuthenticationError("Refresh token doesn't belong to this client")
            
        # Verify token is still active
        if not old_token.is_active:
            raise ValueError("Refresh token has been revoked")
            
        # Verify refresh token is not expired
        if old_token.is_refresh_token_expired():
            raise ValueError("Refresh token has expired")
            
        # Get user
        user = User.get_by_id(old_token.user_id)
        if not user:
            raise ValueError(f"User not found: {old_token.user_id}")
            
        # Revoke old token
        old_token.revoke()
        
        # Create new tokens
        new_access_token = self._generate_jwt_token(
            user_id=user.id,
            evrmore_address=user.evrmore_address,
            token_type="access",
            scope=old_token.scope,
            client_id=client_id
        )
        
        new_refresh_token = self._generate_jwt_token(
            user_id=user.id,
            evrmore_address=user.evrmore_address,
            token_type="refresh",
            scope=old_token.scope,
            client_id=client_id
        )
        
        # Calculate expiration times
        access_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.access_token_expires)
        refresh_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.refresh_token_expires)
        
        # Create token object
        new_token = OAuthToken(
            id=str(uuid.uuid4()),
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            client_id=client_id,
            user_id=user.id,
            scope=old_token.scope,
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at
        )
        
        # Save to database
        if not new_token.save():
            raise Exception("Failed to save OAuth token")
            
        # Trigger hooks
        self._run_hooks('on_token_refreshed', 
                       token=new_token,
                       client_id=client_id,
                       user_id=old_token.user_id,
                       scope=old_token.scope)
            
        if self.debug:
            logger.debug(f"Refreshed token for user {user.id} and client {client_id}")
            
        return new_token
    
    def revoke_oauth_token(self, token: str, client_id: str, client_secret: str) -> bool:
        """Revoke an OAuth 2.0 token.
        
        Args:
            token: Access or refresh token
            client_id: OAuth client ID
            client_secret: OAuth client secret
            
        Returns:
            bool: True if token was revoked, False otherwise
            
        Raises:
            AuthenticationError: If client authentication fails
        """
        from .models import OAuthClient, OAuthToken
        from .exceptions import AuthenticationError
        
        # Verify client
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            raise AuthenticationError(f"Invalid client_id: {client_id}")
            
        # Verify client secret
        if not client.verify_client_secret(client_secret):
            raise AuthenticationError("Invalid client_secret")
            
        # Try to find token by access token
        token_obj = OAuthToken.get_by_access_token(token)
        
        # If not found, try to find by refresh token
        if not token_obj:
            token_obj = OAuthToken.get_by_refresh_token(token)
            
        # If still not found, return success (token doesn't exist)
        if not token_obj:
            return True
            
        # Verify token belongs to this client
        if token_obj.client_id != client_id:
            raise AuthenticationError("Token doesn't belong to this client")
            
        # If token is already revoked, return success
        if not token_obj.is_active:
            return True
            
        # Revoke token
        result = token_obj.revoke()
        
        # Trigger hooks if revocation was successful
        if result:
            self._run_hooks('on_token_revoked', 
                          token=token_obj,
                          client_id=client_id,
                          token_id=token_obj.id)
                
            if self.debug:
                logger.debug(f"Revoked token for user {token_obj.user_id} and client {client_id}")
                
        return result
    
    def validate_oauth_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate an OAuth 2.0 token.
        
        Args:
            token: OAuth token string
            
        Returns:
            Dict[str, Any]: Token payload if valid, None otherwise
        """
        if not token:
            return None
            
        # First, validate the JWT
        payload = self.validate_token(token)
        if not payload:
            return None
            
        # Check if it's an access token
        if payload.get("type") != "access":
            logger.warning("Token is not an access token")
            return None
            
        # Verify the token exists in the database
        oauth_token = OAuthToken.get_by_access_token(token)
        if not oauth_token:
            logger.warning("Token not found in database")
            return None
            
        # Verify the token is not expired
        if oauth_token.is_access_token_expired():
            logger.warning("Token is expired")
            return None
            
        # Debug log
        if self.debug:
            logger.debug(f"OAuth token validated: {payload}")
            
        return {
            "user_id": payload["sub"],
            "evrmore_address": payload["address"],
            "scope": payload["scope"],
            "client_id": payload.get("client_id"),
            "expires_at": payload["exp"]
        }

    def _load_rsa_keys(self, private_key_path: str, public_key_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Load RSA keys from files."""
        private_key = None
        public_key = None
        
        try:
            if private_key_path and os.path.exists(private_key_path):
                with open(private_key_path, 'r') as f:
                    private_key = f.read()
                    logger.debug(f"Loaded RSA private key from {private_key_path}")
            else:
                logger.warning(f"Private key file not found: {private_key_path}")
                
            if public_key_path and os.path.exists(public_key_path):
                with open(public_key_path, 'r') as f:
                    public_key = f.read()
                    logger.debug(f"Loaded RSA public key from {public_key_path}")
            else:
                logger.warning(f"Public key file not found: {public_key_path}")
                
        except Exception as e:
            logger.error(f"Error loading RSA keys: {str(e)}")
            
        return private_key, public_key

    def _generate_jwt_token(self, user_id: str, evrmore_address: str, 
                           expiration: int = None, 
                           token_type: str = "access", 
                           scope: str = "profile",
                           client_id: str = None) -> str:
        """Generate a JWT token for a user.
        
        Args:
            user_id: User ID
            evrmore_address: Evrmore wallet address
            expiration: Expiration time in seconds
            token_type: Type of token (access or refresh)
            scope: OAuth 2.0 scope
            client_id: OAuth client ID (for OAuth tokens)
            
        Returns:
            str: JWT token
        """
        # Set expiration if not provided
        if expiration is None:
            expiration = self.access_token_expires if token_type == "access" else self.refresh_token_expires
            
        # Generate unique token ID (jti)
        token_id = str(uuid.uuid4())
        
        # Set claims
        now = datetime.datetime.utcnow()
        payload = {
            # Standard JWT claims
            "sub": user_id,  # Subject (user ID)
            "iss": self.jwt_issuer,  # Issuer
            "aud": self.jwt_audience,  # Audience
            "jti": token_id,  # JWT ID
            "iat": now,  # Issued at
            "exp": now + datetime.timedelta(seconds=expiration),  # Expiration
            
            # Custom claims
            "address": evrmore_address,  # Evrmore address
            "type": token_type,  # Token type (access or refresh)
            "scope": scope,  # OAuth 2.0 scope
        }
        
        # Add client_id for OAuth tokens
        if client_id:
            payload["client_id"] = client_id
            
        # Debug log
        if self.debug:
            logger.debug(f"Generating {token_type} token for user {user_id} with expiration {expiration} seconds")
            logger.debug(f"Token payload: {payload}")
            
        # Determine key based on algorithm
        key = None
        if self.jwt_algorithm.startswith('RS'):
            key = self.private_key
            if not key:
                logger.error("Private key not available for RS256 signing")
                raise Exception("Private key not available for RS256 signing")
        else:
            key = self.jwt_secret
            
        # Generate token
        try:
            token = jwt.encode(
                payload,
                key,
                algorithm=self.jwt_algorithm
            )
            return token
        except Exception as e:
            logger.error(f"Error generating JWT token: {str(e)}")
            raise e 