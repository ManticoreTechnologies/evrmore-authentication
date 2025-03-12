# SQLite Implementation

This document describes how Evrmore Authentication uses SQLite as a backend storage system.

## Overview

Evrmore Authentication uses SQLite as a lightweight, file-based database that requires no external server. SQLite provides a simple and reliable way to store and retrieve session data, user information, and authentication challenges.

## Database Schema

The SQLite implementation uses a simple relational database schema with the following tables:

| Table | Description |
|-------|-------------|
| `users` | Stores user data |
| `challenges` | Stores authentication challenges |
| `sessions` | Stores user sessions and tokens |

## Table Schemas

### Users Table

```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    evrmore_address TEXT UNIQUE NOT NULL,
    username TEXT,
    email TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
)
```

### Challenges Table

```sql
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    challenge_text TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
```

### Sessions Table

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
```

## Data Models

The SQLite implementation uses dataclass models to represent the database tables:

### User Model

```python
@dataclass
class User:
    id: str
    evrmore_address: str
    username: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    last_login: Optional[datetime.datetime] = None
```

### Challenge Model

```python
@dataclass
class Challenge:
    id: str
    user_id: str
    challenge_text: str
    expires_at: datetime.datetime
    used: bool = False
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
```

### Session Model

```python
@dataclass
class Session:
    id: str
    user_id: str
    token: str
    expires_at: datetime.datetime
    is_active: bool = True
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
```

## Handling Datetime Objects

SQLite doesn't natively support datetime objects, so they are stored as ISO format strings in the database and converted back to datetime objects when retrieving them.

```python
def to_dict(self):
    """Convert User to a dictionary."""
    return {
        "id": str(self.id),
        "evrmore_address": self.evrmore_address,
        "username": self.username,
        "email": self.email,
        "is_active": self.is_active,
        "created_at": self.created_at.isoformat() if self.created_at else None,
        "last_login": self.last_login.isoformat() if self.last_login else None
    }
```

## Database Connections

The SQLite implementation uses a singleton pattern to manage database connections, ensuring that only one connection is active at a time:

```python
class SQLiteManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SQLiteManager, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self):
        if not self.initialized:
            db_path = os.environ.get('SQLITE_DB_PATH', './data/evrmore_auth.db')
            
            # Create data directory if it doesn't exist
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._create_tables()
            self.initialized = True
```

## Configuration Options

SQLite connection settings can be configured using environment variables:

```
SQLITE_DB_PATH=./data/evrmore_auth.db  # Path to the SQLite database file
``` 