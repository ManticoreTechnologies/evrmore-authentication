# Evrmore Authentication Directory Structure

This document outlines the directory structure of the Evrmore Authentication project.

## Project Organization

```
evrmore-authentication-dev/
│── data/                        # Root-level data directory (consider moving contents to evrmore_authentication/data)
│── dist/                        # Distribution files for packaging
│── docs/                        # Documentation files
│
│── evrmore_authentication/      # Core authentication module
│   ├── bin/                     # Executable scripts
│   ├── data/                    # Database and other data storage
│   ├── examples/                # Example scripts demonstrating functionality
│   ├── tests/                   # Test directory
│   │   ├── unit/                # Unit tests (testing individual functions)
│   │   ├── integration/         # Integration tests (verifying API endpoints)
│   │   ├── e2e/                 # End-to-end tests (full OAuth flow, JWT validation)
│   │   └── __init__.py          
│   ├── __init__.py              # Package initialization
│   ├── api.py                   # API endpoints
│   ├── auth.py                  # Core authentication logic
│   ├── crypto.py                # Cryptographic signing & verification
│   ├── database.py              # Database interactions
│   ├── dependencies.py          # External dependencies
│   ├── exceptions.py            # Custom exceptions
│   ├── models.py                # Database models
│   └── utils.py                 # Utility functions (if needed)
│
│── scripts/                     # CLI scripts and utilities
│   ├── db_manage.py             # Database management utilities
│   ├── run_api_server.py        # API server runner
│   ├── verify_signature.py      # Signature verification tool
│   └── run_web_demo.py          # Web demo runner
│
│── .env                         # Environment variables (actual configuration) 
│── .env.example                 # Example environment variables (template)
│── .gitignore                   # Git ignore rules
│── LICENSE                      # Project license
│── mkdocs.yml                   # Documentation configuration
│── pyproject.toml               # Poetry configuration (if using Poetry)
│── README.md                    # Project README
│── requirements.txt             # Python dependencies
└── setup.py                     # Installation setup
```

## Directory Descriptions

### Core Package

- **evrmore_authentication/**: The main Python package
  - **bin/**: Command-line tools and executables
  - **data/**: Contains database files and other data storage
  - **examples/**: Contains example scripts to demonstrate usage
  - **tests/**: Contains all test files, organized by type

### Testing Structure

- **tests/unit/**: Tests for individual components in isolation
- **tests/integration/**: Tests for API endpoints and component interactions
- **tests/e2e/**: Tests for complete workflows from start to finish

### Scripts

- **scripts/**: Contains utility scripts for managing and running the application
  - **db_manage.py**: Database management utilities
  - **run_api_server.py**: Script to run the API server
  - **verify_signature.py**: Tool to verify Evrmore signatures

### Configuration

- **.env**: Contains actual configuration values
- **.env.example**: Contains example configuration, used as a template

## Usage Notes

1. Use the scripts in the `scripts/` directory for common tasks like running the API server
2. Example code is available in `evrmore_authentication/examples/`
3. Tests can be run using pytest targeting the appropriate test directory

## Development Guidelines

1. Add new core functionality to the appropriate file in `evrmore_authentication/`
2. Add tests for new functionality in the appropriate test directory
3. Keep examples simple and focused on demonstrating specific features
4. Update documentation when adding new features 