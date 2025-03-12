"""FastAPI dependencies for Evrmore Authentication.

This module provides dependencies that can be used in FastAPI endpoints
for authentication and user management.
"""

import jwt
import logging
from typing import Optional, Union
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set up security schemes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
security = HTTPBearer(auto_error=False)

# Import models and auth
from .models import User
from .auth import EvrmoreAuth
from .exceptions import InvalidTokenError, UserNotFoundError

# Initialize auth
auth = EvrmoreAuth()

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    authorization: Optional[str] = Header(None)
) -> User:
    """Get the current authenticated user.
    
    This dependency extracts the JWT token from either the Authorization header
    or the OAuth2 token and validates it to get the current user.
    
    Args:
        token (str, optional): OAuth2 token
        authorization (str, optional): Authorization header
        
    Returns:
        User: The authenticated user
        
    Raises:
        HTTPException: If authentication fails
    """
    # Extract token from authorization header if provided
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Validate the token
        payload = auth.validate_token(token)
        
        # Get user ID from token
        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError("Token does not contain user ID")
        
        # Get user from database directly
        user = User.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(user_id)
        
        return user
        
    except Exception as e:
        logger.warning(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    authorization: Optional[str] = Header(None)
) -> Optional[User]:
    """Get the current user if authenticated, or None if not.
    
    This dependency is similar to get_current_user but doesn't raise an exception
    if the user is not authenticated.
    
    Args:
        token (str, optional): OAuth2 token
        authorization (str, optional): Authorization header
        
    Returns:
        User or None: The authenticated user or None if not authenticated
    """
    # Extract token from authorization header if provided
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    
    if not token:
        return None
    
    try:
        return await get_current_user(token=token)
    except HTTPException:
        return None 