# Development Guide

This guide provides information for developers who want to contribute to the Evrmore Authentication project.

## Setting Up the Development Environment

1. Clone the repository:

```bash
git clone https://github.com/manticoretechnologies/evrmore-authentication.git
cd evrmore-authentication
```

2. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the package in development mode:

```bash
pip3 install -e .
```

4. Install development dependencies:

```bash
pip3 install pytest pytest-cov black flake8 mypy
```

## Project Structure

```
evrmore-authentication/
├── evrmore_authentication/    # Main package
│   ├── __init__.py            # Package initialization
│   ├── auth.py                # Core authentication logic
│   ├── api.py                 # FastAPI endpoints
│   ├── models.py              # Database models
│   ├── exceptions.py          # Custom exceptions
│   └── dependencies.py        # FastAPI dependencies
├── scripts/                   # Utility scripts
│   ├── run_api_server.py      # API server runner
│   └── run_web_demo.py        # Web demo runner
├── examples/                  # Example applications
├── tests/                     # Test suite
├── docs/                      # Documentation
└── setup.py                   # Package setup
```

## Running Tests

Run the test suite:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=evrmore_authentication
```

## Code Style

This project follows PEP 8 style guidelines. You can check your code with:

```bash
flake8 evrmore_authentication
```

Format your code with:

```bash
black evrmore_authentication
```

## Building Documentation

The documentation is built using MkDocs with the Material theme:

```bash
# Install MkDocs and the Material theme
pip3 install mkdocs-material

# Serve the documentation locally
mkdocs serve

# Build the documentation
mkdocs build
```

## Release Process

1. Update the version number in `setup.py`
2. Update the changelog
3. Create a new release on GitHub
4. Build and upload the package to PyPI:

```bash
python3 -m build
python3 -m twine upload dist/*
```

## Contributing Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests to ensure they pass
5. Submit a pull request

Please follow these guidelines when contributing:

- Write clear, concise commit messages
- Include tests for new features
- Update documentation for any changes
- Follow the existing code style

## License

This project is licensed under the MIT License - see the LICENSE file for details. 