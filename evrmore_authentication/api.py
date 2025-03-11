"""
REST API for Evrmore Authentication

This module provides a standalone REST API for Evrmore authentication services.
It can be used to run a dedicated authentication server that other applications
can connect to for handling authentication.
"""

import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import EvrmoreAuth
from .exceptions import (
    AuthenticationError, 
    UserNotFoundError, 
    ChallengeExpiredError,
    ChallengeAlreadyUsedError,
    InvalidSignatureError, 
    InvalidTokenError,
    SessionExpiredError
)
from .dependencies import get_current_user

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Evrmore Authentication API",
    description="REST API for Evrmore blockchain-based authentication",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize authentication service
auth = EvrmoreAuth()

# Exception handler
@app.exception_handler(AuthenticationError)
async def authentication_exception_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=401,
        content={"error": str(exc)},
    )

# Pydantic models for request/response
class ChallengeRequest(BaseModel):
    evrmore_address: str = Field(..., description="Evrmore wallet address")
    expire_minutes: Optional[int] = Field(None, description="Minutes until challenge expires")

class ChallengeResponse(BaseModel):
    challenge: str = Field(..., description="Challenge to be signed")
    expires_at: datetime = Field(..., description="Expiration time of the challenge")
    expires_in_minutes: int = Field(..., description="Minutes until expiration")

class AuthenticationRequest(BaseModel):
    evrmore_address: str = Field(..., description="Evrmore wallet address")
    challenge: str = Field(..., description="Challenge that was signed")
    signature: str = Field(..., description="Signature produced by wallet")
    token_expire_minutes: Optional[int] = Field(None, description="Minutes until token expires")

class TokenResponse(BaseModel):
    token: str = Field(..., description="JWT access token")
    user_id: str = Field(..., description="User ID")
    evrmore_address: str = Field(..., description="Evrmore address")
    expires_at: datetime = Field(..., description="Token expiration time")

class TokenValidationResponse(BaseModel):
    valid: bool = Field(..., description="Whether the token is valid")
    user_id: Optional[str] = Field(None, description="User ID if token is valid")
    evrmore_address: Optional[str] = Field(None, description="Evrmore address if token is valid")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")

class TokenInvalidationRequest(BaseModel):
    token: str = Field(..., description="JWT token to invalidate")

class TokenInvalidationResponse(BaseModel):
    success: bool = Field(..., description="Whether invalidation was successful")

class UserResponse(BaseModel):
    id: str = Field(..., description="User ID")
    evrmore_address: str = Field(..., description="Evrmore wallet address")
    username: Optional[str] = Field(None, description="Username")
    email: Optional[str] = Field(None, description="Email address")
    is_active: bool = Field(..., description="Whether user is active")
    created_at: datetime = Field(..., description="Creation time")
    last_login: Optional[datetime] = Field(None, description="Last login time")


# API routes
@app.get("/", tags=["Root"])
async def read_root():
    """Health check endpoint."""
    return {
        "status": "ok",
        "name": "Evrmore Authentication API",
        "version": "1.0.0",
        "evrmore_node_available": auth.evrmore_available
    }

@app.post("/challenge", response_model=ChallengeResponse, tags=["Authentication"])
async def generate_challenge(request: ChallengeRequest):
    """Generate a challenge for a user to sign with their Evrmore wallet."""
    try:
        # Calculate expiry time
        expire_minutes = request.expire_minutes
        if expire_minutes is None:
            expire_minutes_str = os.getenv("CHALLENGE_EXPIRE_MINUTES", "10")
            try:
                expire_minutes = int(expire_minutes_str)
            except (ValueError, TypeError):
                expire_minutes = 10  # Default to 10 minutes if parsing fails
        
        # Generate the challenge
        challenge_text = auth.generate_challenge(
            request.evrmore_address,
            expire_minutes=expire_minutes
        )
        
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(minutes=expire_minutes)
        
        return {
            "challenge": challenge_text,
            "expires_at": expires_at,
            "expires_in_minutes": expire_minutes
        }
    except Exception as e:
        logger.error(f"Error generating challenge: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/authenticate", response_model=TokenResponse, tags=["Authentication"])
async def authenticate(request: AuthenticationRequest, user_agent: Optional[str] = Header(None), client_host: Optional[str] = Header(None)):
    """Authenticate a user using their signed challenge."""
    try:
        user_session = auth.authenticate(
            evrmore_address=request.evrmore_address,
            challenge=request.challenge,
            signature=request.signature,
            ip_address=client_host,
            user_agent=user_agent,
            token_expire_minutes=request.token_expire_minutes
        )
        
        return {
            "token": user_session.token,
            "user_id": user_session.user_id,
            "evrmore_address": user_session.evrmore_address,
            "expires_at": user_session.expires_at
        }
    except AuthenticationError as e:
        error_type = type(e).__name__
        logger.error(f"Authentication error ({error_type}): {str(e)}")
        
        if isinstance(e, ChallengeExpiredError):
            status_code = 401
            detail = "Authentication challenge has expired. Please request a new challenge."
        elif isinstance(e, InvalidSignatureError):
            status_code = 401
            detail = (
                f"Invalid signature provided for address {request.evrmore_address}. "
                f"Please ensure you are signing the exact challenge text with the correct wallet. "
                f"Tips: 1) Copy the entire challenge text including prefix, 2) Make sure there are no "
                f"extra spaces, 3) Use the correct case for your address, 4) Try with or without the "
                f"prefix 'Sign this message to authenticate with Evrmore: ' in your wallet."
            )
        elif isinstance(e, UserNotFoundError):
            status_code = 404
            detail = f"User with address {request.evrmore_address} not found."
        elif isinstance(e, ChallengeAlreadyUsedError):
            status_code = 400
            detail = "This challenge has already been used. Please request a new challenge."
        else:
            status_code = 400
            detail = str(e)
            
        raise HTTPException(status_code=status_code, detail=detail)

@app.get("/validate", response_model=TokenValidationResponse, tags=["Tokens"])
async def validate_token(token: str):
    """Validate a JWT token and return its payload."""
    try:
        token_data = auth.validate_token(token)
        print(f"Token data: {token_data}")
        return {
            "valid": True,
            "user_id": token_data.get("sub"),
            "evrmore_address": token_data.get("addr"),
            "expires_at": datetime.fromtimestamp(token_data.get("exp"))
        }
    except Exception as e:
        logger.warning(f"Token validation failed: {str(e)}")
        print(f"Token validation error: {str(e)}")
        return {"valid": False}

@app.post("/logout", response_model=TokenInvalidationResponse, tags=["Authentication"])
async def logout(request: TokenInvalidationRequest):
    """Invalidate a JWT token (logout)."""
    try:
        success = auth.invalidate_token(request.token)
        return {"success": success}
    except Exception as e:
        logger.error(f"Error logging out: {str(e)}")
        return {"success": False}

@app.get("/me", response_model=UserResponse, tags=["Users"])
async def get_current_user_info(user = Depends(get_current_user)):
    """Get information about the currently authenticated user."""
    return {
        "id": str(user.id),
        "evrmore_address": user.evrmore_address,
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login": user.last_login
    }

def run_api(host="0.0.0.0", port=8000, **kwargs):
    """
    Run the API server.
    
    Args:
        host (str): Host to bind to
        port (int): Port to bind to
        **kwargs: Additional arguments to pass to uvicorn.run
    """
    import uvicorn
    uvicorn.run("evrmore_authentication.api:app", host=host, port=port, **kwargs)

if __name__ == "__main__":
    # Run the API server when this module is executed directly
    run_api() 