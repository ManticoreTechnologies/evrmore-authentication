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
    
    def __init__(self, db: Optional[Session] = None):
        """Initialize the Evrmore Authentication system.
        
        Args:
            db (Optional[Session]): SQLAlchemy database session
                If not provided, a new session will be created when needed.
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
    
    def _get_db(self) -> Session:
        """Get a database session.
        
        Returns:
            Session: SQLAlchemy database session
        """
        if self.db is not None:
            return self.db
        return next(get_db())
    
    def generate_challenge(
        self, 
        evrmore_address: str, 
        expire_minutes: int = CHALLENGE_EXPIRE_MINUTES
    ) -> str:
        """Generate a unique challenge for a user to sign.
        
        Args:
            evrmore_address (str): The Evrmore wallet address
            expire_minutes (int, optional): Minutes until challenge expires. 
                Defaults to CHALLENGE_EXPIRE_MINUTES.
                
        Returns:
            str: Challenge text to be signed by the user's wallet
        
        Raises:
            AuthenticationError: If there is an error generating the challenge
        """
        try:
            # Validate that the address is a valid Evrmore address
            # This is just a basic check - the verifymessage call will do a more thorough check
            if not evrmore_address or len(evrmore_address) < 20:
                raise AuthenticationError("Invalid Evrmore address format")
            
            # Generate a unique challenge with timestamp to prevent replay attacks
            timestamp = datetime.datetime.utcnow().isoformat()
            random_data = secrets.token_hex(16)
            challenge_text = (
                f"Sign this message to authenticate with Evrmore Auth: "
                f"{random_data} at {timestamp}"
            )
            
            db = self._get_db()
            
            # Find or create user
            user = db.query(User).filter(User.evrmore_address == evrmore_address).first()
            
            if not user:
                user = User(evrmore_address=evrmore_address)
                db.add(user)
                db.flush()
            
            # Create challenge
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
            challenge = Challenge(
                user_id=user.id,
                challenge_text=challenge_text,
                expires_at=expires_at,
                used=False
            )
            
            db.add(challenge)
            db.commit()
            
            return challenge_text
            
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Database error while generating challenge: {str(e)}")
            raise AuthenticationError(f"Failed to generate challenge: {str(e)}")
        except Exception as e:
            logger.error(f"Error generating challenge: {str(e)}")
            raise AuthenticationError(f"Failed to generate challenge: {str(e)}")
    
    def authenticate(
        self, 
        evrmore_address: str, 
        challenge: str, 
        signature: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        token_expire_minutes: int = JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    ) -> UserSession:
        """Authenticate a user using their signed challenge.
        
        Args:
            evrmore_address (str): The Evrmore wallet address
            challenge (str): The challenge text that was signed
            signature (str): The signature created by signing the challenge
            ip_address (Optional[str], optional): User's IP address. Defaults to None.
            user_agent (Optional[str], optional): User's agent string. Defaults to None.
            token_expire_minutes (int, optional): Minutes until token expires. 
                Defaults to JWT_ACCESS_TOKEN_EXPIRE_MINUTES.
                
        Returns:
            UserSession: Session data including the JWT token
            
        Raises:
            UserNotFoundError: If user with the address is not found
            ChallengeExpiredError: If the challenge has expired
            ChallengeAlreadyUsedError: If the challenge has already been used
            InvalidSignatureError: If signature verification fails
            AuthenticationError: For other authentication errors
        """
        db = self._get_db()
        
        try:
            # Find the user
            user = db.query(User).filter(User.evrmore_address == evrmore_address).first()
            if not user:
                raise UserNotFoundError(evrmore_address)
            
            # Find the most recent unused challenge
            challenge_obj = (
                db.query(Challenge)
                .filter(
                    Challenge.user_id == user.id,
                    Challenge.challenge_text == challenge,
                    Challenge.used == False
                )
                .order_by(Challenge.created_at.desc())
                .first()
            )
            
            if not challenge_obj:
                raise AuthenticationError("Challenge not found")
            
            if challenge_obj.is_expired:
                raise ChallengeExpiredError(challenge_obj.id)
            
            if challenge_obj.used:
                raise ChallengeAlreadyUsedError(challenge_obj.id)
            
            # Verify the signature using Evrmore RPC
            try:
                # Use the real Evrmore client to verify the message
                if not self.evrmore_client:
                    raise InvalidSignatureError("Evrmore client not available")
                    
                is_valid = self.evrmore_client.verifymessage(
                    evrmore_address,
                    signature,
                    challenge
                )
                
                if not is_valid:
                    raise InvalidSignatureError(evrmore_address)
                    
            except Exception as e:
                logger.error(f"Error during signature verification: {str(e)}")
                raise InvalidSignatureError(f"{str(e)}")
            
            # Mark challenge as used in an atomic transaction
            challenge_obj.used = True
            
            # Generate JWT token
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expire_minutes)
            token_data = {
                "sub": str(user.id),
                "addr": evrmore_address,
                "exp": int(expires_at.timestamp()),
                "iat": int(datetime.datetime.utcnow().timestamp()),
                "jti": str(uuid.uuid4())
            }
            
            token = jwt.encode(
                token_data,
                self.jwt_secret,
                algorithm=JWT_ALGORITHM
            )
            
            # Create session
            session = DBSession(
                user_id=user.id,
                token=token,
                expires_at=expires_at,
                is_active=True,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Update user's last login time
            user.last_login = datetime.datetime.utcnow()
            
            db.add(session)
            db.commit()
            
            return UserSession(
                user_id=str(user.id),
                evrmore_address=user.evrmore_address,
                token=token,
                expires_at=expires_at
            )
            
        except (
            UserNotFoundError,
            ChallengeExpiredError,
            ChallengeAlreadyUsedError,
            InvalidSignatureError
        ) as e:
            db.rollback()
            logger.warning(f"Authentication failed: {str(e)}")
            raise
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Database error during authentication: {str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
        except Exception as e:
            db.rollback()
            logger.error(f"Error during authentication: {str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate a JWT token and return the payload.
        
        Args:
            token (str): JWT token to validate
            
        Returns:
            Dict[str, Any]: JWT payload containing user information
            
        Raises:
            InvalidTokenError: If token is invalid or expired
        """
        try:
            # Decode the token with our JWT secret
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[JWT_ALGORITHM]
            )
            
            # Check if token is in the database and active
            db = self._get_db()
            session = (
                db.query(DBSession)
                .filter(DBSession.token == token, DBSession.is_active == True)
                .first()
            )
            
            if not session:
                raise InvalidTokenError()
                
            if session.is_expired:
                raise SessionExpiredError(session.id)
            
            return payload
        except (jwt.PyJWTError, jwt.DecodeError, jwt.InvalidTokenError):
            raise InvalidTokenError()
        
    def get_user_by_token(self, token: str) -> User:
        """Get user by JWT token.
        
        Args:
            token (str): JWT token
            
        Returns:
            User: User object
            
        Raises:
            InvalidTokenError: If token is invalid
            UserNotFoundError: If user is not found
        """
        payload = self.validate_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise InvalidTokenError()
        
        db = self._get_db()
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise UserNotFoundError(user_id)
            
        return user
    
    def invalidate_token(self, token: str) -> bool:
        """Invalidate a JWT token (logout).
        
        Args:
            token (str): JWT token to invalidate
            
        Returns:
            bool: True if token was invalidated, False otherwise
        """
        db = self._get_db()
        
        try:
            session = db.query(DBSession).filter(DBSession.token == token).first()
            if not session:
                return False
                
            session.is_active = False
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
    
    def invalidate_all_tokens(self, user_id: Union[str, uuid.UUID]) -> bool:
        """Invalidate all tokens for a user.
        
        Args:
            user_id (Union[str, uuid.UUID]): User ID
            
        Returns:
            bool: True if tokens were invalidated, False otherwise
        """
        db = self._get_db()
        
        try:
            db.query(DBSession).filter(
                DBSession.user_id == user_id,
                DBSession.is_active == True
            ).update({"is_active": False})
            
            db.commit()
            return True
        except SQLAlchemyError:
            db.rollback()
            return False
            
    def create_wallet_address(self) -> str:
        """Create a new Evrmore wallet address.
        
        Returns:
            str: The new Evrmore address
            
        Raises:
            AuthenticationError: If there is an error creating the address
        """
        if not self.evrmore_client:
            raise AuthenticationError("Evrmore client not available")
            
        try:
            # Call the getnewaddress RPC method to create a new address
            new_address = self.evrmore_client.getnewaddress()
            return new_address
        except Exception as e:
            logger.error(f"Error creating new wallet address: {str(e)}")
            raise AuthenticationError(f"Failed to create wallet address: {str(e)}")
            
    def sign_message(self, address: str, message: str) -> str:
        """Sign a message with the specified Evrmore address.
        
        Note: This requires that the wallet containing this address is unlocked.
        
        Args:
            address (str): The Evrmore address to sign with
            message (str): The message to sign
            
        Returns:
            str: The signature
            
        Raises:
            AuthenticationError: If there is an error signing the message
        """
        if not self.evrmore_client:
            raise AuthenticationError("Evrmore client not available")
            
        try:
            # Call the signmessage RPC method to sign the message
            signature = self.evrmore_client.signmessage(address, message)
            return signature
        except Exception as e:
            logger.error(f"Error signing message: {str(e)}")
            raise AuthenticationError(f"Failed to sign message: {str(e)}") 