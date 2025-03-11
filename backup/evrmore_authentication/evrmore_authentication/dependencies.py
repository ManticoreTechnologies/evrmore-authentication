"""Dependency injection utilities for web frameworks.

This module provides dependencies for integrating with web frameworks
like FastAPI.
"""

import os
from typing import Optional
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from .auth import EvrmoreAuth
from .models import User
from .exceptions import InvalidTokenError, UserNotFoundError

# OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Auth instance
auth = EvrmoreAuth()

def get_current_user(
    token: str = Depends(oauth2_scheme),
    authorization: Optional[str] = Header(None)
) -> User:
    """Get the current authenticated user from a JWT token.
    
    This function can be used as a FastAPI dependency to inject
    the current user into route handlers.
    
    Args:
        token (str, optional): JWT token from OAuth2 scheme
        authorization (Optional[str], optional): Authorization header
    
    Returns:
        User: User object for the authenticated user
    
    Raises:
        HTTPException: 401 if token is invalid or 404 if user not found
    """
    # Allow token to be passed via Authorization header or OAuth2 scheme
    auth_token = None
    
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            auth_token = parts[1]
    
    # Use OAuth2 token if Authorization header token is not available
    if not auth_token:
        auth_token = token
    
    try:
        user = auth.get_user_by_token(auth_token)
        return user
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    authorization: Optional[str] = Header(None)
) -> Optional[User]:
    """Get the current authenticated user or None if not authenticated.
    
    Similar to get_current_user but doesn't raise exceptions if token is
    missing or invalid.
    
    Args:
        token (Optional[str], optional): JWT token from OAuth2 scheme
        authorization (Optional[str], optional): Authorization header
    
    Returns:
        Optional[User]: User object for the authenticated user or None
    """
    # Allow token to be passed via Authorization header or OAuth2 scheme
    auth_token = None
    
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            auth_token = parts[1]
    
    # Use OAuth2 token if Authorization header token is not available
    if not auth_token and token:
        auth_token = token
        
    if not auth_token:
        return None
    
    try:
        return auth.get_user_by_token(auth_token)
    except (InvalidTokenError, UserNotFoundError):
        return None 