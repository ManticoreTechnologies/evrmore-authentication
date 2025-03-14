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

from fastapi import FastAPI, Depends, HTTPException, Header, Request, Response, Cookie, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
import secrets
import jwt

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
from .models import OAuthClient, OAuthToken, User

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

# Create OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="oauth/token")

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
    username: Optional[str] = Field(None, description="Username if set")
    email: Optional[str] = Field(None, description="Email if set")
    is_active: bool = Field(..., description="Whether the user is active")
    created_at: datetime = Field(..., description="Creation time")
    last_login: Optional[datetime] = Field(None, description="Last login time")

# OAuth 2.0 models
class OAuthClientRequest(BaseModel):
    client_name: str = Field(..., description="Name of the client application")
    redirect_uris: str = Field(..., description="Comma-separated list of allowed redirect URIs")
    scope: str = Field("profile", description="Default scope for this client")
    grant_types: str = Field("authorization_code,refresh_token", description="Comma-separated list of allowed grant types")
    response_types: str = Field("code", description="Comma-separated list of allowed response types")
    client_uri: Optional[str] = Field(None, description="URI of the client application")

class OAuthClientResponse(BaseModel):
    client_id: str = Field(..., description="Client ID")
    client_secret: str = Field(..., description="Client secret")
    client_name: str = Field(..., description="Name of the client application")
    redirect_uris: str = Field(..., description="Comma-separated list of allowed redirect URIs")
    scope: str = Field(..., description="Default scope for this client")
    grant_types: str = Field(..., description="Comma-separated list of allowed grant types")
    response_types: str = Field(..., description="Comma-separated list of allowed response types")
    client_uri: Optional[str] = Field(None, description="URI of the client application")

class OAuthAuthorizeRequest(BaseModel):
    client_id: str = Field(..., description="Client ID")
    redirect_uri: str = Field(..., description="Redirect URI")
    response_type: str = Field("code", description="Response type")
    scope: str = Field("profile", description="Requested scope")
    state: Optional[str] = Field(None, description="State parameter to prevent CSRF")

class OAuthInitiateLoginRequest(BaseModel):
    """Request to initiate the OAuth login flow."""
    client_id: str = Field(..., description="OAuth client ID")
    redirect_uri: str = Field(..., description="Redirect URI after authentication")
    response_type: str = Field("code", description="OAuth response type")
    scope: str = Field("profile", description="OAuth scope")
    state: Optional[str] = Field(None, description="State parameter to prevent CSRF")

class OAuthChallengeResponse(BaseModel):
    """Response with challenge for the user to sign."""
    challenge: str = Field(..., description="Challenge to sign")
    expires_at: datetime = Field(..., description="When the challenge expires")
    auth_request_id: str = Field(..., description="Auth request ID to track the session")

class OAuthLoginRequest(BaseModel):
    """Request to complete the OAuth login with a signed challenge."""
    evrmore_address: str = Field(..., description="Evrmore address")
    challenge: str = Field(..., description="Challenge that was signed")
    signature: str = Field(..., description="Signature of the challenge")
    auth_request_id: str = Field(..., description="Auth request ID from the challenge request")

class OAuthLoginResponse(BaseModel):
    """Response to a successful login."""
    success: bool = Field(..., description="Whether login was successful")
    redirect_uri: str = Field(..., description="URI to redirect the user to")

class OAuthTokenRequest(BaseModel):
    grant_type: str = Field(..., description="Grant type")
    code: Optional[str] = Field(None, description="Authorization code (for authorization_code grant)")
    redirect_uri: Optional[str] = Field(None, description="Redirect URI (for authorization_code grant)")
    refresh_token: Optional[str] = Field(None, description="Refresh token (for refresh_token grant)")
    client_id: str = Field(..., description="Client ID")
    client_secret: str = Field(..., description="Client secret")

class OAuthTokenResponse(BaseModel):
    access_token: str = Field(..., description="Access token")
    token_type: str = Field("Bearer", description="Token type")
    expires_in: int = Field(..., description="Seconds until the access token expires")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    scope: str = Field(..., description="Granted scope")

class OAuthRevokeRequest(BaseModel):
    token: str = Field(..., description="Token to revoke")
    token_type_hint: Optional[str] = Field(None, description="Token type hint")
    client_id: str = Field(..., description="Client ID")
    client_secret: str = Field(..., description="Client secret")

class OAuthRevokeResponse(BaseModel):
    success: bool = Field(..., description="Whether revocation was successful")

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

# OAuth 2.0 endpoints
@app.post("/oauth/clients", response_model=OAuthClientResponse, tags=["oauth"])
async def register_oauth_client(
    request: OAuthClientRequest,
    current_user: User = Depends(get_current_user)
):
    """Register a new OAuth 2.0 client application."""
    client = auth.register_oauth_client(
        client_name=request.client_name,
        redirect_uris=request.redirect_uris,
        user_id=current_user.id if current_user else None,
        scope=request.scope,
        grant_types=request.grant_types,
        response_types=request.response_types,
        client_uri=request.client_uri
    )
    
    return {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "scope": client.scope,
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "client_uri": client.client_uri
    }

@app.post("/oauth/authorize", response_model=OAuthChallengeResponse, tags=["oauth"])
async def initiate_oauth_authorization(
    request: OAuthInitiateLoginRequest,
    response: Response
):
    """
    Start the OAuth 2.0 authorization process.
    
    This endpoint initiates the login flow by generating a challenge for the user to sign.
    The client should present this challenge to the user for signing with their Evrmore wallet.
    """
    try:
        # Verify client
        client = OAuthClient.get_by_client_id(request.client_id)
        if not client:
            raise HTTPException(status_code=400, detail=f"Invalid client_id: {request.client_id}")
        
        # Verify redirect URI
        if not client.verify_redirect_uri(request.redirect_uri):
            raise HTTPException(status_code=400, detail=f"Invalid redirect_uri: {request.redirect_uri}")
        
        # Verify response type
        if not client.verify_response_type(request.response_type):
            raise HTTPException(status_code=400, detail=f"Unsupported response_type: {request.response_type}")
        
        # Create a secure auth request ID to track this authorization
        auth_request_id = secrets.token_urlsafe(16)
        
        # Store the OAuth parameters in a secure cookie
        oauth_params = {
            "client_id": request.client_id,
            "redirect_uri": request.redirect_uri,
            "response_type": request.response_type,
            "scope": request.scope,
            "state": request.state,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Set secure cookie with OAuth parameters
        cookie_value = jwt.encode(
            oauth_params, 
            auth.jwt_secret, 
            algorithm="HS256"
        )
        
        # Set cookies with multiple paths to ensure they're available
        cookie_name = f"oauth_params_{auth_request_id}"
        
        # Set at path / to be available everywhere
        response.set_cookie(
            key=cookie_name,
            value=cookie_value,
            httponly=True,
            # secure=True,  # Enable in production
            samesite="lax",
            max_age=1800,  # 30 minutes
            path="/"
        )
        
        # Also set at path /oauth for backward compatibility
        response.set_cookie(
            key=cookie_name,
            value=cookie_value,
            httponly=True,
            # secure=True,  # Enable in production
            samesite="lax",
            max_age=1800,  # 30 minutes
            path="/oauth"
        )
        
        # Generate a challenge for the user to sign
        # Note: We don't have an evrmore_address yet, so we'll use a placeholder
        # The actual challenge text will be generic, not tied to an address
        challenge = f"Sign this message to authenticate with Evrmore: {auth_request_id}:{datetime.utcnow().timestamp()}"
        expires_at = datetime.utcnow() + timedelta(minutes=30)  # Increased from 10 to 30 minutes
        
        logger.info(f"Generated challenge for auth_request_id {auth_request_id}")
        
        return {
            "challenge": challenge,
            "expires_at": expires_at,
            "auth_request_id": auth_request_id
        }
    except Exception as e:
        logger.error(f"Error initiating OAuth login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error initiating OAuth login: {str(e)}")

@app.post("/oauth/login", response_model=OAuthLoginResponse, tags=["oauth"])
async def complete_oauth_login(
    request: OAuthLoginRequest,
    response: Response, 
    request_obj: Request,
    user_agent: Optional[str] = Header(None),
    client_host: Optional[str] = Header(None)
):
    """
    Complete the OAuth 2.0 login process with a signed challenge.
    
    This endpoint verifies the signature and generates an authorization code
    which is sent to the redirect URI.
    """
    try:
        # Get oauth_params from cookies - handle the auth_request_id cookie naming
        auth_request_id = request.auth_request_id
        cookie_name = f"oauth_params_{auth_request_id}"
        cookies = request_obj.cookies
        
        # Check if cookie exists
        oauth_params_cookie = cookies.get(cookie_name)
        if not oauth_params_cookie:
            # Try alternative paths/names as fallback
            for key in cookies.keys():
                if key.endswith(auth_request_id):
                    oauth_params_cookie = cookies[key]
                    break
        
        # Verify we have the OAuth parameters cookie
        if not oauth_params_cookie:
            logger.error(f"Missing OAuth cookie: {cookie_name}")
            
            # Return a more helpful error with debugging info
            cookie_debug = ", ".join(list(cookies.keys())[:5]) + ("..." if len(cookies) > 5 else "")
            error_msg = f"Missing or expired OAuth session. Could not find {cookie_name}. Available cookies: {cookie_debug}"
            
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Decode the OAuth parameters
        try:
            oauth_params = jwt.decode(
                oauth_params_cookie,
                auth.jwt_secret,
                algorithms=["HS256"]
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid OAuth session: {str(e)}")
        
        # Extract parameters
        client_id = oauth_params.get("client_id")
        redirect_uri = oauth_params.get("redirect_uri")
        response_type = oauth_params.get("response_type", "code")
        scope = oauth_params.get("scope", "profile")
        state = oauth_params.get("state")
        
        # Verify the client
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            raise HTTPException(status_code=400, detail=f"Invalid client_id: {client_id}")
        
        # Verify signature
        try:
            # In a simplified flow, we're just using verify_signature_only
            # without full challenge/user management
            if not auth.verify_signature_only(
                request.evrmore_address,
                request.challenge,
                request.signature
            ):
                raise HTTPException(status_code=401, detail="Invalid signature")
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Signature verification failed: {str(e)}")
        
        # Get or create the user
        user = User.get_by_address(request.evrmore_address)
        if not user:
            user = User.create(
                evrmore_address=request.evrmore_address,
                username=None,
                email=None
            )
            logger.info(f"Created new user with address: {request.evrmore_address}")
        
        # Update last login
        user.last_login = datetime.utcnow()
        user.save()
        
        # Create authorization code
        auth_code = auth.create_authorization_code(
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=scope
        )
        
        # Clear the OAuth parameters cookie - try multiple paths
        response.delete_cookie(key=cookie_name, path="/")
        response.delete_cookie(key=cookie_name, path="/oauth")
        response.delete_cookie(key=cookie_name)
        
        # Construct the redirect URI with the authorization code
        final_redirect = f"{redirect_uri}?code={auth_code.code}"
        if state:
            final_redirect += f"&state={state}"
            
        return {
            "success": True,
            "redirect_uri": final_redirect
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error completing OAuth login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error completing OAuth login: {str(e)}")

@app.get("/oauth/authorize", tags=["oauth"])
async def authorize_get_endpoint(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "profile", 
    state: Optional[str] = None
):
    """GET endpoint for OAuth authorization (supports both GET and POST)."""
    login_request = OAuthInitiateLoginRequest(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
        state=state
    )
    
    # Redirect to the frontend authorization page
    auth_url = f"/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type={response_type}&scope={scope}"
    if state:
        auth_url += f"&state={state}"
    
    return RedirectResponse(auth_url)

@app.post("/oauth/token", response_model=OAuthTokenResponse, tags=["oauth"])
async def get_oauth_token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
):
    """Get an OAuth 2.0 token."""
    try:
        logger.info(f"Token request: grant_type={grant_type}, code={code}, client_id={client_id}, redirect_uri={redirect_uri}")

        # Verify client first
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            logger.error(f"Client not found: {client_id}")
            raise HTTPException(status_code=401, detail="Invalid client credentials")
            
        if not client.verify_client_secret(client_secret):
            logger.error(f"Invalid client secret for client: {client_id}")
            raise HTTPException(status_code=401, detail="Invalid client credentials")
            
        logger.info(f"Client verified: {client.client_name}")
        
        if grant_type == "authorization_code":
            # Validate request
            if not code or not redirect_uri:
                logger.error("Missing code or redirect_uri for authorization_code grant")
                raise HTTPException(
                    status_code=400, 
                    detail="code and redirect_uri are required for authorization_code grant"
                )
            
            # Verify redirect URI
            if not client.verify_redirect_uri(redirect_uri):
                logger.error(f"Invalid redirect URI: {redirect_uri} for client: {client_id}")
                raise HTTPException(status_code=400, detail="Invalid redirect URI")
                
            logger.info(f"Exchanging code: {code}")
            
            # Exchange code for token
            token = auth.exchange_code_for_token(
                code=code,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri
            )
            
            # Calculate expires_in
            expires_in = int((token.access_token_expires_at - datetime.utcnow()).total_seconds())
            
            logger.info(f"Token exchange successful for client: {client_id}, user: {token.user_id}")
            
            return {
                "access_token": token.access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": token.refresh_token,
                "scope": token.scope
            }
            
        elif grant_type == "refresh_token":
            # Validate request
            if not refresh_token:
                raise HTTPException(
                    status_code=400, 
                    detail="refresh_token is required for refresh_token grant"
                )
            
            # Refresh token
            token = auth.refresh_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Calculate expires_in
            expires_in = int((token.access_token_expires_at - datetime.utcnow()).total_seconds())
            
            return {
                "access_token": token.access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": token.refresh_token,
                "scope": token.scope
            }
            
        else:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported grant_type: {grant_type}"
            )
    except AuthenticationError as e:
        logger.error(f"OAuth token error: {str(e)}")
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error(f"OAuth token error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/oauth/revoke", response_model=OAuthRevokeResponse, tags=["oauth"])
async def revoke_oauth_token(request: OAuthRevokeRequest):
    """Revoke an OAuth 2.0 token."""
    # Verify client
    client = OAuthClient.get_by_client_id(request.client_id)
    if not client:
        raise HTTPException(status_code=400, detail=f"Invalid client_id: {request.client_id}")
    
    # Verify client secret
    if not client.verify_client_secret(request.client_secret):
        raise HTTPException(status_code=400, detail="Invalid client_secret")
    
    # Revoke token
    success = auth.revoke_oauth_token(request.token)
    
    return {
        "success": success
    }

@app.get("/oauth/userinfo", tags=["oauth"])
async def get_oauth_userinfo(authorization: str = Header(None)):
    """Get information about the authenticated user using an OAuth 2.0 token."""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401, 
                detail="Missing or invalid Authorization header"
            )
        
        token = authorization[7:]  # Remove "Bearer " prefix
        token_info = auth.validate_oauth_token(token)
        
        if not token_info:
            raise HTTPException(
                status_code=401, 
                detail="Invalid token"
            )
        
        # Get user
        user = User.get_by_id(token_info["user_id"])
        if not user:
            raise HTTPException(
                status_code=404, 
                detail=f"User not found: {token_info['user_id']}"
            )
        
        # Return standard OpenID Connect userinfo response
        return {
            "sub": user.id,
            "address": user.evrmore_address,
            "preferred_username": user.username or user.evrmore_address,
            "email": user.email,
            "email_verified": False,  # Email verification not implemented yet
            "updated_at": int(user.last_login.timestamp()) if user.last_login else None
        }
    except Exception as e:
        logger.error(f"OAuth userinfo error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Helper function to get a user from an OAuth token
async def get_user_from_oauth_token(token: str = Depends(oauth2_scheme)):
    """Get a user from an OAuth token."""
    try:
        token_info = auth.validate_oauth_token(token)
        if not token_info:
            raise HTTPException(
                status_code=401, 
                detail="Invalid token"
            )
        
        user = User.get_by_id(token_info["user_id"])
        if not user:
            raise HTTPException(
                status_code=404, 
                detail=f"User not found: {token_info['user_id']}"
            )
        
        return user
    except Exception as e:
        logger.error(f"OAuth token validation error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# Example protected route using OAuth token
@app.get("/oauth/protected", tags=["oauth"])
async def oauth_protected_route(user: User = Depends(get_user_from_oauth_token)):
    """Example protected route that requires OAuth authentication."""
    return {
        "message": f"Hello, {user.evrmore_address}!",
        "user_id": user.id
    }

@app.get("/auth", tags=["oauth"])
async def auth_page(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "profile",
    state: Optional[str] = None,
    response: Response = None
):
    """Display the authentication page for users to enter their Evrmore address and sign the challenge."""
    try:
        # Verify client
        client = OAuthClient.get_by_client_id(client_id)
        if not client:
            return JSONResponse(
                status_code=400,
                content={"detail": f"Invalid client_id: {client_id}"}
            )
        
        # Verify redirect URI
        if not client.verify_redirect_uri(redirect_uri):
            return JSONResponse(
                status_code=400,
                content={"detail": f"Invalid redirect_uri: {redirect_uri}"}
            )
        
        # Create authorization request ID
        auth_request_id = secrets.token_urlsafe(16)
        
        # Store the OAuth parameters in a secure cookie
        oauth_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Set secure cookie with OAuth parameters
        cookie_value = jwt.encode(
            oauth_params, 
            auth.jwt_secret, 
            algorithm="HS256"
        )
        
        # Set the cookie - Path needs to be broader than /oauth to be available on the /auth page
        if response:
            response.set_cookie(
                key=f"oauth_params_{auth_request_id}",
                value=cookie_value,
                httponly=True,
                # secure=True,  # Commented out for development, enable in production
                samesite="lax",
                max_age=1800,  # 30 minutes
                path="/"  # Make cookie available to all paths
            )
        
        # Generate html for authentication page
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Evrmore Authentication</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    line-height: 1.6;
                }}
                h1, h2 {{
                    color: #333;
                    text-align: center;
                }}
                .auth-container {{
                    background-color: #f5f5f5;
                    border-radius: 8px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-top: 20px;
                }}
                .app-info {{
                    background-color: #e8f4f8;
                    border-radius: 8px;
                    padding: 15px;
                    margin-bottom: 20px;
                    text-align: center;
                }}
                .form-group {{
                    margin-bottom: 15px;
                }}
                label {{
                    display: block;
                    margin-bottom: 5px;
                    font-weight: bold;
                }}
                input[type="text"] {{
                    width: 100%;
                    padding: 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }}
                button {{
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    padding: 10px 15px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-weight: bold;
                    width: 100%;
                }}
                .hidden {{
                    display: none;
                }}
                #challenge-text {{
                    background-color: #e9e9e9;
                    padding: 10px;
                    border-radius: 4px;
                    font-family: monospace;
                    margin: 10px 0;
                    word-break: break-all;
                }}
                .error-text {{
                    color: #f44336;
                    margin-top: 10px;
                    text-align: center;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <h1>Evrmore Authentication</h1>
            
            <div class="app-info">
                <p>Application <strong>{client.client_name}</strong> is requesting access to your profile.</p>
            </div>
            
            <div class="auth-container">
                <div id="step1">
                    <h2>Enter your Evrmore Address</h2>
                    <div class="form-group">
                        <label for="evrmore_address">Your Evrmore Address:</label>
                        <input type="text" id="evrmore_address" name="evrmore_address" 
                            placeholder="Enter your Evrmore address" required>
                    </div>
                    <button id="get-challenge-btn">Get Challenge</button>
                </div>
                
                <div id="step2" class="hidden">
                    <h2>Sign this Challenge</h2>
                    <p>Please sign this message with your Evrmore wallet:</p>
                    <div id="challenge-text"></div>
                    <div class="form-group">
                        <label for="signature">Your Signature:</label>
                        <input type="text" id="signature" name="signature" 
                            placeholder="Paste your signature here" required>
                    </div>
                    <button id="verify-signature-btn">Verify Signature</button>
                </div>
                
                <div id="loading" class="hidden">
                    <p>Processing...</p>
                </div>
                
                <div id="error-message" class="hidden" style="color: red; margin-top: 10px;"></div>
            </div>
            
            <script>
                // Store data
                const authData = {{
                    client_id: "{client_id}",
                    redirect_uri: "{redirect_uri}",
                    response_type: "{response_type}",
                    scope: "{scope}",
                    state: "{state}",
                    auth_request_id: "{auth_request_id}"
                }};
                
                // DOM elements
                const step1 = document.getElementById('step1');
                const step2 = document.getElementById('step2');
                const loading = document.getElementById('loading');
                const errorMessage = document.getElementById('error-message');
                const evrmoreAddressInput = document.getElementById('evrmore_address');
                const challengeText = document.getElementById('challenge-text');
                const signatureInput = document.getElementById('signature');
                
                // Event listeners
                document.getElementById('get-challenge-btn').addEventListener('click', getChallenge);
                document.getElementById('verify-signature-btn').addEventListener('click', verifySignature);
                
                // Get challenge
                async function getChallenge() {{
                    const evrmore_address = evrmoreAddressInput.value.trim();
                    if (!evrmore_address) {{
                        showError('Please enter your Evrmore address');
                        return;
                    }}
                    
                    try {{
                        showLoading();
                        
                        const response = await fetch('/oauth/authorize', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{
                                client_id: authData.client_id,
                                redirect_uri: authData.redirect_uri,
                                response_type: authData.response_type,
                                scope: authData.scope,
                                state: authData.state
                            }})
                        }});
                        
                        if (!response.ok) {{
                            const errorData = await response.json();
                            throw new Error(errorData.detail || 'Failed to get challenge');
                        }}
                        
                        const data = await response.json();
                        authData.challenge = data.challenge;
                        authData.auth_request_id = data.auth_request_id;
                        
                        // Display challenge
                        challengeText.textContent = data.challenge;
                        
                        // Switch to step 2
                        step1.classList.add('hidden');
                        step2.classList.remove('hidden');
                        loading.classList.add('hidden');
                        
                    }} catch (error) {{
                        showError(error.message || 'Failed to get challenge');
                    }}
                }}
                
                // Verify signature
                async function verifySignature() {{
                    const signature = signatureInput.value.trim();
                    if (!signature) {{
                        showError('Please enter your signature');
                        return;
                    }}
                    
                    try {{
                        showLoading();
                        
                        const response = await fetch('/oauth/login', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{
                                evrmore_address: evrmoreAddressInput.value.trim(),
                                challenge: authData.challenge,
                                signature: signature,
                                auth_request_id: authData.auth_request_id
                            }})
                        }});
                        
                        if (!response.ok) {{
                            const errorData = await response.json();
                            throw new Error(errorData.detail || 'Failed to verify signature');
                        }}
                        
                        const data = await response.json();
                        
                        // Redirect to client application
                        window.location.href = data.redirect_uri;
                        
                    }} catch (error) {{
                        showError(error.message || 'Failed to verify signature');
                    }}
                }}
                
                // Helper functions
                function showLoading() {{
                    step1.classList.add('hidden');
                    step2.classList.add('hidden');
                    loading.classList.remove('hidden');
                    errorMessage.classList.add('hidden');
                }}
                
                function showError(message) {{
                    loading.classList.add('hidden');
                    errorMessage.textContent = message;
                    errorMessage.classList.remove('hidden');
                }}
            </script>
        </body>
        </html>
        """)
    except Exception as e:
        logger.error(f"Error rendering auth page: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Error rendering auth page: {str(e)}"}
        )

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