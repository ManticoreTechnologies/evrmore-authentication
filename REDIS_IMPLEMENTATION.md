# Redis-Only Implementation for Evrmore Authentication

This document details the changes made to the Evrmore Authentication system to use Redis exclusively for data storage, removing all other database backends.

## Changes Made

### 1. Database Module (`db/__init__.py`)

- Replaced SQLAlchemy with Redis implementation
- Implemented key functions to manage users, challenges, and sessions in Redis:
  - `create_user`, `get_user_by_id`, `get_user_by_address`, `update_user`, `delete_user`
  - `create_challenge`, `get_challenge`, `get_challenge_by_text`, `mark_challenge_used`
  - `create_session`, `get_session`, `get_session_by_token`, `invalidate_session`, `invalidate_all_sessions` 
- Added Redis key helper functions for consistent key naming
- Simplified database initialization (no-op for Redis)

### 2. Data Models (`models.py`)

- Replaced SQLAlchemy ORM models with Redis-compatible dataclasses
- Maintained the same interface for backward compatibility
- Added `from_dict` and `to_dict` methods for easy serialization
- Kept core properties like `is_expired` for challenge and session models

### 3. Authentication Class (`auth.py`)

- Updated `EvrmoreAuth` to use Redis functions instead of SQLAlchemy
- Maintained the same public API for backward compatibility
- Simplified functions by removing database session handling
- Added better error handling tailored to Redis operations

### 4. API Dependencies (`dependencies.py`)

- Updated dependencies to use Redis database functions
- Simplified authentication flow for FastAPI endpoints
- Improved error handling for API routes

### 5. API Server Script (`run_api_server.py`)

- Created a script that exclusively uses Redis
- Added explicit Redis connection testing before starting
- Disabled all other database backends
- Added clear warnings and information about Redis-only mode

### 6. Web Demo

- Updated web demo to use the API server instead of direct database access
- Created API client functions to communicate with the API server
- Simplified web demo app.py by removing direct database handling
- Updated configuration to point to API server

## Redis Data Structure

- **Users:** Hash stored at `evrauth:user:{user_id}` with JSON data
- **Challenges:** Hash stored at `evrauth:challenge:{challenge_id}` with JSON data
- **Sessions:** Hash stored at `evrauth:session:{session_id}` with JSON data
- **Lookups:**
  - Address to user: String at `evrauth:address:{evrmore_address}`
  - Token to session: String at `evrauth:token:{token}`
- **Indexes:**
  - User challenges: Set at `evrauth:challenges:user:{user_id}`
  - User sessions: Set at `evrauth:sessions:user:{user_id}`

## Benefits of Redis Implementation

1. **Performance:** Redis is in-memory, providing faster access than SQLite or PostgreSQL
2. **Simplicity:** No SQL schema management needed
3. **Scalability:** Redis can easily be clustered for higher load
4. **Persistence:** Redis offers various persistence options (RDB, AOF)
5. **Atomicity:** Redis operations are atomic, ensuring data consistency

## Usage

To use the Redis-only implementation:

1. Ensure Redis server is running: `redis-cli ping`
2. Set environment variables in `.env`:
   ```
   DB_TYPE=redis
   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_DB=0
   REDIS_PASSWORD=
   ```
3. Start the API server: `./run_api_server.py`
4. Use the API directly or run the web demo: `cd examples/web_auth_demo && ./run.sh`

## API Endpoints

The API server provides the following endpoints:

- `GET /` - Health check and server info
- `POST /challenge` - Generate a challenge for a user to sign
- `POST /authenticate` - Authenticate with a signed challenge
- `GET /validate` - Validate a JWT token
- `POST /logout` - Invalidate a token (logout)
- `GET /me` - Get current user info (requires authentication)

## Limitations

- Complex queries that would be possible with SQL are more difficult
- Lack of schema enforcement (must be handled in application code)
- Redis data should be backed up regularly for durability 