<!-- omit in toc -->
<div align="center">
  <img src="docs/assets/images/logo.svg" alt="Evrmore Authentication" width="250">
  <h1>Evrmore Authentication</h1>
  
  <p>A secure wallet-based authentication system for Evrmore blockchain applications</p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
  [![PyPI version](https://badge.fury.io/py/evrmore-authentication.svg)](https://badge.fury.io/py/evrmore-authentication)
</div>

<!-- omit in toc -->
## 📋 Table of Contents

- [✨ Overview](#-overview)
- [🚀 Quick Start](#-quick-start)
  - [Installation](#installation)
  - [Running the API Server](#running-the-api-server)
  - [Running the Web Demo](#running-the-web-demo)
- [🧰 System Requirements](#-system-requirements)
- [🔐 Authentication Flow](#-authentication-flow)
- [📘 Usage in Your Application](#-usage-in-your-application)
  - [Basic Authentication Flow](#basic-authentication-flow)
  - [FastAPI Integration](#fastapi-integration)
  - [Advanced Features](#advanced-features)
- [🔧 Debugging & Troubleshooting](#-debugging--troubleshooting)
  - [Debug Mode](#debug-mode)
  - [Database Management](#database-management)
  - [Signature Verification](#signature-verification)
  - [Common Issues](#common-issues)
- [🛠️ Customization](#-customization)
  - [Event Hooks](#event-hooks)
  - [Challenge Ownership Management](#challenge-ownership-management)
  - [Manual Challenge Creation](#manual-challenge-creation)
- [🔌 Extending the Library](#-extending-the-library)
  - [Database Extensions](#database-extensions)
  - [Model Inheritance](#model-inheritance)
  - [Schema Migration Pattern](#schema-migration-pattern)
  - [Custom Authentication Logic](#custom-authentication-logic)
  - [User Management Extensions](#user-management-extensions)
  - [Advanced Query Helpers](#advanced-query-helpers)
- [⚙️ Configuration](#️-configuration)
- [📚 Documentation](#-documentation)
- [💻 Development](#-development)
  - [Project Structure](#project-structure)
  - [Setup Development Environment](#setup-development-environment)
  - [Running Tests](#running-tests)
  - [Building Documentation Locally](#building-documentation-locally)
- [📄 License](#-license)
- [📞 Contact](#-contact)

## ✨ Overview

Evrmore Authentication is a Python package that provides wallet-based authentication using Evrmore signature verification. This allows users to authenticate to web applications using their Evrmore wallet without sharing their private keys, creating a secure and user-friendly authentication experience.

**Key Features:**

- **🔑 Wallet-based authentication** - Users sign a challenge message with their Evrmore wallet
- **🔒 JWT token management** - Secure session handling with JSON Web Tokens
- **📁 SQLite backend** - Simple, file-based database for session and challenge storage
- **👤 Automatic user management** - Users are created on first authentication
- **🌐 Complete API server** - Ready-to-use FastAPI server for authentication endpoints
- **🖥️ Demo web interface** - Example Flask application showing the complete authentication flow
- **🐞 Advanced debugging** - Debug mode and detailed logging for troubleshooting
- **🧩 Event hooks system** - Customize authentication flow with hooks for key events
- **⚡ Utility scripts** - Tools for database management and signature verification
- **🔍 Flexible verification** - Options to skip challenge ownership checks when needed
- **🧹 Database maintenance** - Automated cleanup for expired challenges and sessions
- **🔌 Extensibility** - Built-in extension points for building account management systems

## 🚀 Quick Start

### Installation

```bash
pip3 install evrmore-authentication
```

### Running the API Server

```bash
python3 -m scripts.run_api_server --host 0.0.0.0 --port 8000
```

### Running the Web Demo

```bash
python3 -m scripts.run_web_demo --port 5000 --api-url http://localhost:8000
```

## 🧰 System Requirements

- Python 3.7 or higher
- SQLite database for session and challenge storage

## 🔐 Authentication Flow

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

## 📘 Usage in Your Application

### Basic Authentication Flow

```python
from evrmore_authentication import EvrmoreAuth

# Initialize the authentication system
auth = EvrmoreAuth()

# Generate a challenge for a user's Evrmore address
challenge = auth.generate_challenge("EXaMPLeEvRMoReAddResS")

# Verify the signature provided by the user
session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature="signed_challenge_from_wallet"
)

# Use the token for authentication
token = session.token

# Validate a token
token_data = auth.validate_token(token)

# Get user from token
user = auth.get_user_by_token(token)

# Invalidate a token (logout)
auth.invalidate_token(token)
```

### FastAPI Integration

The package includes a ready-to-use FastAPI server with the following endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenge` | POST | Generate a challenge for a user |
| `/authenticate` | POST | Authenticate with a signed challenge |
| `/validate` | GET | Validate a JWT token |
| `/me` | GET | Get authenticated user information |
| `/logout` | POST | Invalidate a JWT token (logout) |

```python
# Example using the API from a client application
import requests

# Generate a challenge
response = requests.post(
    "http://localhost:8000/challenge",
    json={"evrmore_address": "EXaMPLeEvRMoReAddResS"}
)
challenge_data = response.json()
challenge = challenge_data["challenge"]

# User signs the challenge with their wallet...
signature = "signature_from_wallet"

# Authenticate with the signed challenge
response = requests.post(
    "http://localhost:8000/authenticate",
    json={
        "evrmore_address": "EXaMPLeEvRMoReAddResS",
        "challenge": challenge,
        "signature": signature
    }
)
auth_data = response.json()
token = auth_data["token"]

# Use the token for authenticated requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://localhost:8000/me", headers=headers)
user_data = response.json()
```

### Advanced Features

```python
# Initialize with debug mode
auth = EvrmoreAuth(debug=True)

# Skip challenge ownership check when authenticating
session = auth.authenticate(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge=challenge,
    signature=signature,
    skip_ownership_check=True  # Useful when users share wallets
)

# Directly verify a signature without database interaction
is_valid = auth.verify_signature_only(
    address="EXaMPLeEvRMoReAddResS",
    message="message to verify",
    signature="signature"
)

# Get details about a challenge
challenge_info = auth.get_challenge_details(challenge_text)

# Reassign a challenge to a different user
auth.reassign_challenge(
    challenge_text=challenge_text, 
    new_address="EXaMPLeEvRMoReAddResS"
)

# Create a custom challenge
custom_challenge = auth.create_manual_challenge(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge_text="Custom challenge text"  # Optional - will generate if not provided
)

# Clean up expired records
auth.cleanup_expired_challenges()
auth.cleanup_expired_sessions()

# Create a test wallet address (for development/testing only)
address, wif_key = auth.create_wallet_address()

# Sign a message using a private key (for testing only)
signature = auth.sign_message(wif_key, message)
```

## 🔧 Debugging & Troubleshooting

### Debug Mode

Enable detailed logging to troubleshoot authentication issues:

```python
# Method 1: Set environment variable
import os
os.environ["EVRMORE_AUTH_DEBUG"] = "true"

# Method 2: Pass debug flag when initializing
auth = EvrmoreAuth(debug=True)
```

Debug mode provides detailed logs about:
- Challenge generation and verification
- Database operations
- Signature verification process
- Error causes and context

### Database Management

Use the database management script to inspect and maintain your database:

```bash
# Show database information
python3 -m scripts.db_manage info

# List all users
python3 -m scripts.db_manage list-users

# List challenges for a specific address
python3 -m scripts.db_manage list-challenges -a "EXaMPLeEvRMoReAddResS"

# List active sessions
python3 -m scripts.db_manage list-sessions

# Clean up expired records
python3 -m scripts.db_manage cleanup

# Check database integrity
python3 -m scripts.db_manage check-integrity --fix
```

### Signature Verification

The standalone signature verification tool helps debug signature issues:

```bash
# Verify a signature without database interaction
python3 -m scripts.verify_signature verify "EXaMPLeEvRMoReAddResS" "message" "signature"

# Generate a challenge string in the same format as the auth system
python3 -m scripts.verify_signature challenge "EXaMPLeEvRMoReAddResS"

# Generate a signature for testing (requires private key)
python3 -m scripts.verify_signature sign "private_key_wif" "message"
```

### Common Issues

**Challenge Ownership Errors:**

If you see "Challenge does not belong to this user" errors:

```python
# Option 1: Skip ownership check during authentication
session = auth.authenticate(
    evrmore_address=address,
    challenge=challenge,
    signature=signature,
    skip_ownership_check=True
)

# Option 2: Reassign the challenge to the correct user
auth.reassign_challenge(challenge_text, new_address=address)
```

**Signature Verification Failures:**

If signature verification fails, try:

1. Verify the wallet is signing the exact challenge text
2. Check if your wallet adds a prefix like "Sign this message: " before signing
3. Use the verification tool to test signature format

```bash
# Test signature verification with the exact message format
python3 -m scripts.verify_signature verify "address" "exact_message" "signature"
```

## 🛠️ Customization

### Event Hooks

Add custom logic at key points in the authentication flow:

```python
from evrmore_authentication import EvrmoreAuth

auth = EvrmoreAuth()

# Add a hook before challenge generation
@auth.add_hook('pre_challenge')
def pre_challenge_hook(evrmore_address, expire_minutes):
    print(f"Generating challenge for {evrmore_address}")
    # You can modify parameters or perform additional checks
    return {"custom_data": "value"}

# Add a hook after successful authentication
@auth.add_hook('post_auth')
def post_auth_hook(user, session):
    print(f"User {user.evrmore_address} authenticated successfully")
    # Perform custom actions after authentication
    notify_login(user.id)
```

Available hook points:
- `pre_challenge`: Before generating a challenge
- `post_challenge`: After generating a challenge
- `pre_auth`: Before authenticating a user
- `post_auth`: After successful authentication
- `pre_verify`: Before verifying a signature
- `post_verify`: After verifying a signature

### Challenge Ownership Management

Customize how challenges are created and assigned:

```python
# Reassign a challenge to a different address
auth.reassign_challenge(
    challenge_text="Sign this message...", 
    new_address="EXaMPLeEvRMoReAddResS"
)

# Create a new challenge and optionally specify its text
challenge = auth.create_manual_challenge(
    evrmore_address="EXaMPLeEvRMoReAddResS",
    challenge_text="Custom challenge text",  # Optional
    expire_minutes=15  # Optional
)
```

### Manual Challenge Creation

Create challenges through the CLI for testing:

```bash
# Create a challenge for an address with custom expiration
python3 -m scripts.db_manage create-challenge "EXaMPLeEvRMoReAddResS" -e 30

# Create a challenge with custom text
python3 -m scripts.db_manage create-challenge "EXaMPLeEvRMoReAddResS" -t "Custom challenge text"
```

## 🔌 Extending the Library

This library is designed to be extended for building more comprehensive account management systems. Here's how to extend it for an `evrmore-accounts` library or similar projects:

### Database Extensions

The SQLite manager is designed to be extended for additional tables:

```python
from evrmore_authentication.models import SQLiteManager

# Extend the database manager
class ExtendedSQLiteManager(SQLiteManager):
    def _create_tables(self):
        # Call the parent method to create core tables
        super()._create_tables()
        
        # Add your custom tables
        cursor = self.conn.cursor()
        
        # Create Profile table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            display_name TEXT,
            bio TEXT,
            avatar_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create additional tables as needed
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            setting_key TEXT NOT NULL,
            setting_value TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        self.conn.commit()
```

To use your extended manager, set it as the singleton instance:

```python
# Replace the SQLiteManager singleton with your extended version
SQLiteManager._instance = ExtendedSQLiteManager()
```

### Model Inheritance

Extend the base models to add your own functionality:

```python
from evrmore_authentication.models import User, SQLiteManager
from dataclasses import dataclass, field
from typing import Optional, List
import datetime

@dataclass
class Profile:
    """User profile with additional information."""
    id: str
    user_id: str
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    
    # Virtual relationship
    user: Optional[User] = None
    
    @classmethod
    def get_by_user_id(cls, user_id):
        """Get profile by user ID."""
        db = SQLiteManager()
        row = db.fetchone("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
        return cls.from_row(row)
    
    @classmethod
    def from_row(cls, row):
        """Create a Profile from a database row."""
        if not row:
            return None
        
        data = dict(row)
        # Handle datetime conversion
        for field in ["created_at", "updated_at"]:
            if field in data and isinstance(data[field], str):
                data[field] = datetime.datetime.fromisoformat(data[field])
        
        return cls(**data)
    
    def save(self):
        """Save profile to database."""
        db = SQLiteManager()
        profile_dict = self.to_dict()
        
        # Check if profile exists
        existing = db.fetchone("SELECT * FROM profiles WHERE id = ?", (self.id,))
        
        if existing:
            # Update existing profile
            db.execute(
                """UPDATE profiles SET 
                user_id = ?, display_name = ?, bio = ?, avatar_url = ?,
                created_at = ?, updated_at = ? WHERE id = ?""",
                (self.user_id, self.display_name, self.bio, self.avatar_url,
                 profile_dict["created_at"], profile_dict["updated_at"], self.id)
            )
        else:
            # Insert new profile
            db.execute(
                """INSERT INTO profiles 
                (id, user_id, display_name, bio, avatar_url, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.id, self.user_id, self.display_name, self.bio, self.avatar_url,
                 profile_dict["created_at"], profile_dict["updated_at"])
            )
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "display_name": self.display_name,
            "bio": self.bio,
            "avatar_url": self.avatar_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
```

### Schema Migration Pattern

Implementing migrations for schema evolution:

```python
class Migration:
    """Base migration class for schema evolution."""
    
    def __init__(self, db_manager):
        self.db = db_manager
        
    def up(self):
        """Apply the migration."""
        raise NotImplementedError("Subclasses must implement up()")
    
    def down(self):
        """Revert the migration."""
        raise NotImplementedError("Subclasses must implement down()")

class AddProfilesTable(Migration):
    """Migration to add profiles table."""
    
    def up(self):
        """Add profiles table."""
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            display_name TEXT,
            bio TEXT,
            avatar_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
    
    def down(self):
        """Remove profiles table."""
        self.db.execute('DROP TABLE IF EXISTS profiles')

# Migration manager
class MigrationManager:
    """Manages database migrations."""
    
    def __init__(self, db_manager=None):
        self.db = db_manager or SQLiteManager()
        self._setup_migration_table()
        self.migrations = []
        
    def _setup_migration_table(self):
        """Create migrations table if it doesn't exist."""
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        ''')
        
    def register(self, migration_class):
        """Register a migration."""
        self.migrations.append((migration_class.__name__, migration_class))
        return self
    
    def migrate(self):
        """Run pending migrations."""
        # Get applied migrations
        applied = self.db.fetchall("SELECT name FROM migrations")
        applied_names = [row['name'] for row in applied]
        
        # Run pending migrations
        for name, migration_class in self.migrations:
            if name not in applied_names:
                print(f"Applying migration: {name}")
                migration = migration_class(self.db)
                migration.up()
                
                # Record migration
                now = datetime.datetime.utcnow().isoformat()
                self.db.execute(
                    "INSERT INTO migrations (name, applied_at) VALUES (?, ?)",
                    (name, now)
                )
```

Usage:

```python
# Initialize migrations
migration_manager = MigrationManager()
migration_manager.register(AddProfilesTable)
migration_manager.migrate()
```

### Custom Authentication Logic

Extend the authentication system with your own logic:

```python
from evrmore_authentication.auth import EvrmoreAuth

class ExtendedAuth(EvrmoreAuth):
    """Extended authentication with additional features."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add your custom state
        
    def authenticate(self, *args, **kwargs):
        # Call parent method
        session = super().authenticate(*args, **kwargs)
        
        # Add your custom logic after authentication
        user_id = session.user_id
        self._update_user_stats(user_id)
        self._ensure_profile_exists(user_id)
        
        return session
    
    def _update_user_stats(self, user_id):
        """Update user statistics after login."""
        # Implementation here
        pass
        
    def _ensure_profile_exists(self, user_id):
        """Make sure user has a profile record."""
        from your_module import Profile
        
        # Check if profile exists
        profile = Profile.get_by_user_id(user_id)
        if not profile:
            # Create profile
            import uuid
            profile = Profile(
                id=str(uuid.uuid4()),
                user_id=user_id
            )
            profile.save()
```

### User Management Extensions

Add methods for enhanced user management:

```python
class UserManager:
    """User management extensions."""
    
    def __init__(self, auth=None):
        self.auth = auth or EvrmoreAuth()
        self.db = SQLiteManager()
        
    def create_user(self, evrmore_address, username=None, email=None):
        """Create a new user with profile."""
        # Create the user
        import uuid
        user_id = str(uuid.uuid4())
        
        user = User(
            id=user_id,
            evrmore_address=evrmore_address,
            username=username,
            email=email
        )
        user.save()
        
        # Create associated profile
        from your_module import Profile
        profile = Profile(
            id=str(uuid.uuid4()),
            user_id=user_id,
            display_name=username or f"User_{user_id[:8]}"
        )
        profile.save()
        
        return user
        
    def search_users(self, query, limit=20):
        """Search users by address, username or email."""
        query = f"%{query}%"  # SQL LIKE pattern
        
        users = self.db.fetchall(
            """SELECT * FROM users 
            WHERE evrmore_address LIKE ? OR username LIKE ? OR email LIKE ?
            LIMIT ?""",
            (query, query, query, limit)
        )
        
        return [User.from_row(row) for row in users]
        
    def get_user_details(self, user_id):
        """Get complete user details including profile."""
        user = User.get_by_id(user_id)
        if not user:
            return None
            
        from your_module import Profile
        profile = Profile.get_by_user_id(user_id)
        
        result = user.to_dict()
        result["profile"] = profile.to_dict() if profile else None
        
        return result
```

### Advanced Query Helpers

Add helpers for common complex queries:

```python
class QueryHelpers:
    """Helpers for complex database queries."""
    
    @staticmethod
    def get_active_user_count():
        """Get count of active users in the system."""
        db = SQLiteManager()
        result = db.fetchone("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        return result['count'] if result else 0
    
    @staticmethod
    def find_duplicate_addresses():
        """Find duplicate Evrmore addresses (shouldn't happen but helps in debugging)."""
        db = SQLiteManager()
        rows = db.fetchall(
            """SELECT evrmore_address, COUNT(*) as count 
            FROM users 
            GROUP BY evrmore_address 
            HAVING count > 1"""
        )
        return rows
    
    @staticmethod
    def get_users_with_expired_sessions():
        """Get users with expired but not cleaned up sessions."""
        db = SQLiteManager()
        now = datetime.datetime.utcnow().isoformat()
        
        users = db.fetchall(
            """SELECT DISTINCT u.* 
            FROM users u
            JOIN sessions s ON u.id = s.user_id
            WHERE s.expires_at < ? AND s.is_active = 1""",
            (now,)
        )
        
        return [User.from_row(row) for row in users]
    
    @staticmethod
    def run_custom_query(query, params=None):
        """Run a custom query with parameters."""
        db = SQLiteManager()
        return db.fetchall(query, params)
```

## ⚙️ Configuration

Configuration is done through environment variables or a `.env` file:

```ini
# SQLite configuration
SQLITE_DB_PATH=./data/evrmore_auth.db

# JWT configuration
JWT_SECRET=your-secure-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Challenge configuration
CHALLENGE_EXPIRE_MINUTES=10

# Debug mode
EVRMORE_AUTH_DEBUG=false

# Logging
LOG_LEVEL=INFO
```

## 📚 Documentation

For more information, please see:

- [📖 User Guide](docs/user-guide/index.md)
- [🐞 Debugging & Advanced Features](docs/user-guide/debugging.md)
- [🔍 API Reference](docs/api-reference/index.md)
- [💽 SQLite Implementation](docs/api-reference/sqlite.md)
- [📔 Online Documentation](https://manticoretechnologies.github.io/evrmore-authentication/)

## 💻 Development

### Project Structure

```
evrmore-authentication/
├── evrmore_authentication/    # Main package
│   ├── __init__.py            # Package initialization
│   ├── auth.py                # Core authentication logic
│   ├── api.py                 # FastAPI endpoints
│   ├── models.py              # Database models (SQLite)
│   ├── exceptions.py          # Custom exceptions
│   └── dependencies.py        # FastAPI dependencies
├── scripts/                   # Utility scripts
│   ├── run_api_server.py      # API server runner
│   ├── run_web_demo.py        # Web demo runner
│   ├── db_manage.py           # Database management tool
│   └── verify_signature.py    # Signature verification tool
├── examples/                  # Example applications
│   ├── demo.py                # Simple CLI demo
│   └── web_auth_demo/         # Web application example
├── tests/                     # Test suite
├── docs/                      # Documentation
└── setup.py                   # Package setup
```

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/manticoretechnologies/evrmore-authentication.git
cd evrmore-authentication

# Install in development mode
pip3 install -e .

# Create a .env file
cp .env.example .env
# Edit .env with your configuration

# Initialize the database
python3 -m scripts.db_manage init
```

### Running Tests

```bash
pytest
```

### Building Documentation Locally

```bash
# Install MkDocs and the Material theme
pip3 install mkdocs-material

# Serve the documentation locally at http://127.0.0.1:8000
mkdocs serve

# Build the documentation
mkdocs build
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact

<div align="center">
  <table>
    <tr>
      <td align="center"><b>🏢 Organization</b></td>
      <td><a href="https://manticore.technology">Manticore Technologies</a></td>
    </tr>
    <tr>
      <td align="center"><b>🌐 Website</b></td>
      <td><a href="https://manticore.technology">manticore.technology</a></td>
    </tr>
    <tr>
      <td align="center"><b>📂 GitHub</b></td>
      <td><a href="https://github.com/manticoretechnologies">github.com/manticoretechnologies</a></td>
    </tr>
    <tr>
      <td align="center"><b>✉️ Email</b></td>
      <td><a href="mailto:dev@manticore.technology">dev@manticore.technology</a></td>
    </tr>
  </table>
</div>

---

<div align="center">
  <p>Built with ❤️ by <a href="https://manticore.technology">Manticore Technologies</a></p>
</div> 