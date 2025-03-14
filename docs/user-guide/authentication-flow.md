# Authentication Flow

The Evrmore Authentication system implements a secure, wallet-based authentication flow that leverages the cryptographic capabilities of the Evrmore blockchain. This page explains the authentication process in detail.

## Overview

<div align="center">
  <table>
    <tr>
      <td align="center"><b>1. Challenge Generation</b></td>
      <td>The server generates a unique challenge for the user's Evrmore address</td>
    </tr>
    <tr>
      <td align="center"><b>2. Signature Creation</b></td>
      <td>The user signs the challenge with their Evrmore wallet</td>
    </tr>
    <tr>
      <td align="center"><b>3. Verification</b></td>
      <td>The server verifies the signature against the challenge</td>
    </tr>
    <tr>
      <td align="center"><b>4. Token Issuance</b></td>
      <td>Upon successful verification, a JWT token is issued</td>
    </tr>
    <tr>
      <td align="center"><b>5. Authentication</b></td>
      <td>The token is used for subsequent API requests</td>
    </tr>
  </table>
</div>

## Step 1: Challenge Generation

When a user attempts to authenticate, the server generates a unique challenge for their Evrmore address.

```python
# Server-side code
from evrmore_authentication import EvrmoreAuth

auth = EvrmoreAuth()
challenge = auth.generate_challenge("EXaMPLeEvRMoReAddResS")
```

**What happens behind the scenes:**

1. The system creates a unique challenge text, typically a random string with a timestamp
2. The challenge is stored in the database with:
   - The user's Evrmore address
   - Creation timestamp
   - Expiration timestamp (default: 15 minutes)
3. A `user_challenges` record is created to track challenge ownership
4. Event hooks (if defined) are triggered for challenge generation

**API Endpoint:**

```
POST /challenge
{
  "evrmore_address": "EXaMPLeEvRMoReAddResS"
}
```

The response includes the challenge text:

```json
{
  "challenge": "Sign this message to authenticate: a8f7e9d1c2b3a4f5e6d7c8b9a1f2e3d4",
  "expires_at": "2023-03-14T15:30:45Z"
}
```

## Step 2: Signature Creation

The user signs the challenge with their Evrmore wallet. This is typically done client-side using wallet software or an extension.

**Example using evrmore-cli:**

```bash
evrmore-cli signmessage "EXaMPLeEvRMoReAddResS" "Sign this message to authenticate: a8f7e9d1c2b3a4f5e6d7c8b9a1f2e3d4"
```

The output is a base64-encoded signature:

```
H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH...
```

## Step 3: Verification

The server verifies the signature against the challenge and the Evrmore address.

```python
# Server-side code
session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature="H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH..."
)
```

**What happens behind the scenes:**

1. The system retrieves the challenge from the database and ensures it:
   - Exists
   - Belongs to the specified Evrmore address
   - Hasn't expired
   - Hasn't been used before
2. The signature is verified cryptographically against the challenge and address
3. The challenge is marked as used to prevent replay attacks
4. Event hooks (if defined) are triggered for successful authentication
5. If a user doesn't exist in the database, they are created automatically

**API Endpoint:**

```
POST /authenticate
{
  "evrmore_address": "EXaMPLeEvRMoReAddResS",
  "challenge": "Sign this message to authenticate: a8f7e9d1c2b3a4f5e6d7c8b9a1f2e3d4",
  "signature": "H9LJFkR+a0MFm1jSvmoBZ1wQobuSGPQ2C1TW/m9FVwnQJNjyZLX3ZzOOHI01jEL59YtJFXBH9PnwH..."
}
```

## Step 4: Token Issuance

Upon successful verification, a JWT (JSON Web Token) is generated and issued to the user.

```python
# The authenticate method returns a session with a token
token = session.token
```

**What happens behind the scenes:**

1. A new session is created in the database with:
   - User ID
   - JWT token
   - Creation timestamp
   - Expiration timestamp (default: 30 minutes)
2. The JWT is signed using the configured secret key and algorithm
3. The token contains claims including:
   - User ID
   - Evrmore address
   - Expiration time
   - Issuance time

**API Response:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXZybW9yZV9hZGRyZXNzIjoiRVhhTVBMZUV2Uk1vUmVBZGRSZXNTIiwiZXhwIjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "expires_at": "2023-03-14T16:00:45Z",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "evrmore_address": "EXaMPLeEvRMoReAddResS"
  }
}
```

## Step 5: Authentication

The JWT token is used for subsequent API requests to authenticate the user.

```python
# Client-side code for making authenticated requests
import requests

headers = {
    "Authorization": f"Bearer {token}"
}

response = requests.get("https://api.example.com/protected-resource", headers=headers)
```

**What happens behind the scenes:**

1. The server extracts the token from the Authorization header
2. The token is verified to ensure:
   - It's properly signed
   - It hasn't expired
   - It hasn't been revoked
3. The user information is extracted from the token
4. The request proceeds with the authenticated user context

**API Endpoint for Token Validation:**

```
GET /validate
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "valid": true,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "evrmore_address": "EXaMPLeEvRMoReAddResS"
  }
}
```

## Logout Process

To invalidate a token (logout):

```python
# Server-side code
auth.invalidate_token(token)
```

**What happens behind the scenes:**

1. The session associated with the token is marked as inactive
2. The token can no longer be used for authentication
3. Event hooks (if defined) are triggered for logout

**API Endpoint:**

```
POST /logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Security Considerations

The Evrmore Authentication flow offers several security benefits:

1. **No Password Storage**: The system never stores user passwords, eliminating password database theft risks.

2. **Challenge-Response Mechanism**: Each authentication requires a new challenge, preventing replay attacks.

3. **Cryptographic Verification**: Uses blockchain-grade cryptography to verify signatures.

4. **Short-lived Challenges**: Challenges expire quickly (default: 15 minutes) to limit attack windows.

5. **Single-Use Challenges**: Each challenge can only be used once, preventing replay attacks.

6. **JWT Best Practices**: Implements security best practices for JWT handling.

7. **Database Integrity**: Challenges and sessions are tracked in the database to prevent misuse.

For additional security, consider implementing:

- Rate limiting for challenge generation
- IP-based restrictions
- Additional user verification methods
- Hardware wallet support 