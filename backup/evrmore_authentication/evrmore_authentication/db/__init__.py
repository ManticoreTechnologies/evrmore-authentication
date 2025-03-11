"""Redis database management for Evrmore Authentication.

This module provides Redis connectivity for the Evrmore Authentication system.
All data is stored in Redis instead of a relational database.
"""

import os
import json
import uuid
import redis
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Redis configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_PREFIX = "evrauth:"

# Create Redis client
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True
)

# Test Redis connection
try:
    redis_client.ping()
    logger.info(f"Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
except redis.ConnectionError as e:
    logger.error(f"Failed to connect to Redis: {str(e)}")
    raise Exception(f"Redis connection failed: {str(e)}")

def get_redis():
    """Get the Redis client.
    
    Returns:
        Redis: Redis client instance
    """
    return redis_client

# Helper functions for keys
def _user_key(user_id):
    """Get the Redis key for a user."""
    return f"{REDIS_PREFIX}user:{user_id}"

def _user_by_address_key(address):
    """Get the Redis key for a user by address."""
    return f"{REDIS_PREFIX}address:{address}"

def _challenge_key(challenge_id):
    """Get the Redis key for a challenge."""
    return f"{REDIS_PREFIX}challenge:{challenge_id}"

def _challenges_by_user_key(user_id):
    """Get the Redis key for challenges by user."""
    return f"{REDIS_PREFIX}challenges:user:{user_id}"

def _session_key(session_id):
    """Get the Redis key for a session."""
    return f"{REDIS_PREFIX}session:{session_id}"

def _sessions_by_user_key(user_id):
    """Get the Redis key for sessions by user."""
    return f"{REDIS_PREFIX}sessions:user:{user_id}"

def _token_key(token):
    """Get the Redis key for a token."""
    return f"{REDIS_PREFIX}token:{token}"

# User management functions
def create_user(evrmore_address, username=None, email=None):
    """Create a new user.
    
    Args:
        evrmore_address (str): The user's Evrmore address
        username (str, optional): The user's username
        email (str, optional): The user's email
        
    Returns:
        dict: The created user
    """
    r = get_redis()
    
    # Check if user with this address already exists
    existing_user_id = r.get(_user_by_address_key(evrmore_address))
    if existing_user_id:
        user_data = r.hgetall(_user_key(existing_user_id))
        if user_data:
            return json.loads(user_data.get("data", "{}"))
    
    # Create new user
    user_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    user = {
        "id": user_id,
        "evrmore_address": evrmore_address,
        "username": username,
        "email": email,
        "is_active": True,
        "created_at": now,
        "last_login": None
    }
    
    # Store user data
    r.hset(_user_key(user_id), "data", json.dumps(user))
    r.set(_user_by_address_key(evrmore_address), user_id)
    
    return user

def get_user_by_id(user_id):
    """Get a user by ID.
    
    Args:
        user_id (str): The user's ID
        
    Returns:
        dict: The user or None if not found
    """
    r = get_redis()
    user_data = r.hgetall(_user_key(user_id))
    if not user_data:
        return None
    
    return json.loads(user_data.get("data", "{}"))

def get_user_by_address(evrmore_address):
    """Get a user by Evrmore address.
    
    Args:
        evrmore_address (str): The user's Evrmore address
        
    Returns:
        dict: The user or None if not found
    """
    r = get_redis()
    user_id = r.get(_user_by_address_key(evrmore_address))
    if not user_id:
        return None
    
    return get_user_by_id(user_id)

def update_user(user_id, **kwargs):
    """Update a user.
    
    Args:
        user_id (str): The user's ID
        **kwargs: The fields to update
        
    Returns:
        dict: The updated user
    """
    r = get_redis()
    user_data = r.hgetall(_user_key(user_id))
    if not user_data:
        return None
    
    user = json.loads(user_data.get("data", "{}"))
    
    # Update fields
    for key, value in kwargs.items():
        if key in user:
            user[key] = value
    
    # Store updated user
    r.hset(_user_key(user_id), "data", json.dumps(user))
    
    return user

def delete_user(user_id):
    """Delete a user.
    
    Args:
        user_id (str): The user's ID
        
    Returns:
        bool: True if successful
    """
    r = get_redis()
    user_data = r.hgetall(_user_key(user_id))
    if not user_data:
        return False
    
    user = json.loads(user_data.get("data", "{}"))
    
    # Delete user data
    r.delete(_user_key(user_id))
    r.delete(_user_by_address_key(user["evrmore_address"]))
    
    # Delete challenges and sessions
    challenge_ids = r.smembers(_challenges_by_user_key(user_id))
    for challenge_id in challenge_ids:
        r.delete(_challenge_key(challenge_id))
    
    session_ids = r.smembers(_sessions_by_user_key(user_id))
    for session_id in session_ids:
        session_data = r.hgetall(_session_key(session_id))
        if session_data:
            token = json.loads(session_data.get("data", "{}")).get("token")
            if token:
                r.delete(_token_key(token))
        r.delete(_session_key(session_id))
    
    r.delete(_challenges_by_user_key(user_id))
    r.delete(_sessions_by_user_key(user_id))
    
    return True

# Challenge management functions
def create_challenge(user_id, challenge_text, expires_at):
    """Create a new challenge.
    
    Args:
        user_id (str): The user's ID
        challenge_text (str): The challenge text
        expires_at (datetime): When the challenge expires
        
    Returns:
        dict: The created challenge
    """
    r = get_redis()
    
    challenge_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    challenge = {
        "id": challenge_id,
        "user_id": user_id,
        "challenge_text": challenge_text,
        "created_at": now,
        "expires_at": expires_at.isoformat(),
        "used": False
    }
    
    # Store challenge data
    r.hset(_challenge_key(challenge_id), "data", json.dumps(challenge))
    r.sadd(_challenges_by_user_key(user_id), challenge_id)
    
    # Set expiration
    ttl = int((expires_at - datetime.utcnow()).total_seconds())
    if ttl > 0:
        r.expire(_challenge_key(challenge_id), ttl)
    
    return challenge

def get_challenge(challenge_id):
    """Get a challenge by ID.
    
    Args:
        challenge_id (str): The challenge ID
        
    Returns:
        dict: The challenge or None if not found
    """
    r = get_redis()
    challenge_data = r.hgetall(_challenge_key(challenge_id))
    if not challenge_data:
        return None
    
    return json.loads(challenge_data.get("data", "{}"))

def get_challenge_by_text(challenge_text):
    """Get a challenge by its text.
    
    Args:
        challenge_text (str): The challenge text
        
    Returns:
        dict: The challenge or None if not found
    """
    r = get_redis()
    
    # Get all challenge keys
    challenge_keys = r.keys(f"{REDIS_PREFIX}challenge:*")
    
    for key in challenge_keys:
        challenge_data = r.hgetall(key)
        if not challenge_data:
            continue
        
        challenge = json.loads(challenge_data.get("data", "{}"))
        if challenge.get("challenge_text") == challenge_text:
            return challenge
    
    return None

def mark_challenge_used(challenge_id):
    """Mark a challenge as used.
    
    Args:
        challenge_id (str): The challenge ID
        
    Returns:
        dict: The updated challenge
    """
    r = get_redis()
    challenge_data = r.hgetall(_challenge_key(challenge_id))
    if not challenge_data:
        return None
    
    challenge = json.loads(challenge_data.get("data", "{}"))
    challenge["used"] = True
    
    # Store updated challenge
    r.hset(_challenge_key(challenge_id), "data", json.dumps(challenge))
    
    return challenge

# Session management functions
def create_session(user_id, token, expires_at, ip_address=None, user_agent=None):
    """Create a new session.
    
    Args:
        user_id (str): The user's ID
        token (str): The JWT token
        expires_at (datetime): When the session expires
        ip_address (str, optional): The client's IP address
        user_agent (str, optional): The client's user agent
        
    Returns:
        dict: The created session
    """
    r = get_redis()
    
    session_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    session = {
        "id": session_id,
        "user_id": user_id,
        "token": token,
        "created_at": now,
        "expires_at": expires_at.isoformat(),
        "is_active": True,
        "ip_address": ip_address,
        "user_agent": user_agent
    }
    
    # Store session data
    r.hset(_session_key(session_id), "data", json.dumps(session))
    r.sadd(_sessions_by_user_key(user_id), session_id)
    r.set(_token_key(token), session_id)
    
    # Set expiration
    ttl = int((expires_at - datetime.utcnow()).total_seconds())
    if ttl > 0:
        r.expire(_session_key(session_id), ttl)
        r.expire(_token_key(token), ttl)
    
    return session

def get_session(session_id):
    """Get a session by ID.
    
    Args:
        session_id (str): The session ID
        
    Returns:
        dict: The session or None if not found
    """
    r = get_redis()
    session_data = r.hgetall(_session_key(session_id))
    if not session_data:
        return None
    
    return json.loads(session_data.get("data", "{}"))

def get_session_by_token(token):
    """Get a session by token.
    
    Args:
        token (str): The JWT token
        
    Returns:
        dict: The session or None if not found
    """
    r = get_redis()
    session_id = r.get(_token_key(token))
    if not session_id:
        return None
    
    return get_session(session_id)

def invalidate_session(session_id):
    """Invalidate a session.
    
    Args:
        session_id (str): The session ID
        
    Returns:
        dict: The updated session
    """
    r = get_redis()
    session_data = r.hgetall(_session_key(session_id))
    if not session_data:
        return None
    
    session = json.loads(session_data.get("data", "{}"))
    session["is_active"] = False
    
    # Store updated session
    r.hset(_session_key(session_id), "data", json.dumps(session))
    
    # Delete token mapping
    r.delete(_token_key(session.get("token", "")))
    
    return session

def invalidate_all_sessions(user_id):
    """Invalidate all sessions for a user.
    
    Args:
        user_id (str): The user's ID
        
    Returns:
        int: Number of sessions invalidated
    """
    r = get_redis()
    session_ids = r.smembers(_sessions_by_user_key(user_id))
    count = 0
    
    for session_id in session_ids:
        session = invalidate_session(session_id)
        if session:
            count += 1
    
    return count

# Initialize database
def init_db():
    """Initialize the Redis database.
    
    This is a no-op for Redis, but included for API compatibility.
    """
    logger.info("Redis is ready to use. No initialization needed.")
    return True 