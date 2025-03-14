# OAuth 2.0 API Reference

This document provides detailed information about the OAuth 2.0 endpoints available in the Evrmore Authentication system.

## OAuth 2.0 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/clients` | POST | Register a new OAuth client |
| `/oauth/authorize` | GET/POST | Start the authorization process |
| `/auth` | GET | HTML authentication page for the OAuth flow |
| `/oauth/login` | POST | Authenticate with a signed challenge |
| `/oauth/token` | POST | Exchange authorization codes or refresh tokens |
| `/oauth/userinfo` | GET | Get the authenticated user's profile |
| `/oauth/revoke` | POST | Revoke tokens |

## Client Registration

### Register a new OAuth client

```
POST /oauth/clients
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client_name` | string | Yes | Display name of the client application |
| `redirect_uris` | array of strings | Yes | Allowed redirect URIs |
| `client_uri` | string | No | URI of the client application |
| `logo_uri` | string | No | URI to the client's logo |
| `scopes` | array of strings | No | Allowed scopes (defaults to `["profile"]`) |
| `response_types` | array of strings | No | Allowed response types (defaults to `["code"]`) |

**Example Request:**

```json
{
  "client_name": "Example App",
  "redirect_uris": ["https://example.com/callback"],
  "client_uri": "https://example.com",
  "logo_uri": "https://example.com/logo.png",
  "scopes": ["profile", "email"],
  "response_types": ["code"]
}
```

**Response:**

```json
{
  "client_id": "d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0",
  "client_secret": "XBBMQM9kppmbCyT5opG5FCZ0g89osYeKkrlNrmbIfKk",
  "client_name": "Example App",
  "redirect_uris": ["https://example.com/callback"],
  "client_uri": "https://example.com",
  "logo_uri": "https://example.com/logo.png",
  "scopes": ["profile", "email"],
  "response_types": ["code"],
  "created_at": "2023-03-14T12:00:00Z"
}
```

## Authorization Flow

### 1. Initiate Authorization

```
GET /oauth/authorize
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client_id` | string | Yes | The client identifier |
| `redirect_uri` | string | Yes | Redirect URI registered with the client |
| `response_type` | string | Yes | Must be `code` |
| `scope` | string | Yes | Space-separated list of requested scopes |
| `state` | string | Yes | Random string to prevent CSRF attacks |

**Example Request:**

```
GET /oauth/authorize?client_id=d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0&redirect_uri=https://example.com/callback&response_type=code&scope=profile+email&state=random_state
```

**Response:**

The user is redirected to the authentication page (`/auth`) where they can enter their Evrmore address and sign the challenge.

### 2. Authenticate with a Signed Challenge

After the user signs the challenge, the client submits:

```
POST /oauth/login
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `evrmore_address` | string | Yes | User's Evrmore address |
| `challenge` | string | Yes | The challenge text |
| `signature` | string | Yes | The signature created by the wallet |
| `client_id` | string | Yes | The client identifier |
| `redirect_uri` | string | Yes | The redirect URI |
| `state` | string | Yes | The state parameter |

**Example Request:**

```json
{
  "evrmore_address": "EXaMPLeEvRMoReAddResS",
  "challenge": "Sign this message to authenticate: a8f7e9d1c2b3a4f5e6d7c8b9a1f2e3d4",
  "signature": "H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH...",
  "client_id": "d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0",
  "redirect_uri": "https://example.com/callback",
  "state": "random_state"
}
```

**Response:**

The user is redirected to the `redirect_uri` with an authorization code:

```
https://example.com/callback?code=abcdef123456&state=random_state
```

### 3. Exchange Authorization Code for Tokens

```
POST /oauth/token
```

**Request Parameters (x-www-form-urlencoded):**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `authorization_code` |
| `code` | string | Yes | The authorization code |
| `redirect_uri` | string | Yes | Must match the original redirect URI |
| `client_id` | string | Yes | The client identifier |
| `client_secret` | string | Yes | The client secret |

**Example Request:**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=abcdef123456&redirect_uri=https://example.com/callback&client_id=d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0&client_secret=XBBMQM9kppmbCyT5opG5FCZ0g89osYeKkrlNrmbIfKk
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA...",
  "scope": "profile email"
}
```

## Token Operations

### Get User Information

```
GET /oauth/userinfo
```

**Headers:**

| Header | Value | Required | Description |
|--------|-------|----------|-------------|
| `Authorization` | `Bearer {access_token}` | Yes | The access token |

**Example Request:**

```
GET /oauth/userinfo
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**

```json
{
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "address": "EXaMPLeEvRMoReAddResS",
  "preferred_username": "User_123e4567",
  "email": "user@example.com",
  "email_verified": false
}
```

### Refresh Access Token

```
POST /oauth/token
```

**Request Parameters (x-www-form-urlencoded):**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `refresh_token` |
| `refresh_token` | string | Yes | The refresh token |
| `client_id` | string | Yes | The client identifier |
| `client_secret` | string | Yes | The client secret |

**Example Request:**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA...&client_id=d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0&client_secret=XBBMQM9kppmbCyT5opG5FCZ0g89osYeKkrlNrmbIfKk
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token...",
  "scope": "profile email"
}
```

### Revoke Token

```
POST /oauth/revoke
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to revoke (access or refresh) |
| `client_id` | string | Yes | The client identifier |
| `client_secret` | string | Yes | The client secret |

**Example Request:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_id": "d5fdcc0c-7a88-4cfc-a1ff-6af04b92e9b0",
  "client_secret": "XBBMQM9kppmbCyT5opG5FCZ0g89osYeKkrlNrmbIfKk"
}
```

**Response:**

```json
{
  "success": true
}
```

## Error Responses

OAuth endpoints follow standard OAuth 2.0 error responses. For example:

```json
{
  "error": "invalid_request",
  "error_description": "Invalid client_id parameter"
}
```

Common error types:

| Error | Description |
|-------|-------------|
| `invalid_request` | The request is missing a required parameter or is malformed |
| `unauthorized_client` | The client is not authorized to request an authorization code |
| `access_denied` | The resource owner denied the request |
| `unsupported_response_type` | The server does not support the requested response type |
| `invalid_scope` | The requested scope is invalid or unknown |
| `server_error` | An unexpected error occurred on the server |
| `temporarily_unavailable` | The server is temporarily unavailable |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | The authorization code or refresh token is invalid |

## Implementation Notes

1. All dates/times are in ISO 8601 format (UTC).
2. Access tokens expire after 1 hour by default.
3. Refresh tokens expire after 30 days by default.
4. The `/auth` endpoint serves an HTML page for the user authentication flow.
5. The state parameter is used to prevent CSRF attacks and should be validated by the client.
6. Client secrets should never be exposed to the browser or other insecure environments. 