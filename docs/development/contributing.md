# Contributing Guide

Thank you for your interest in contributing to the Evrmore Authentication project! This guide will help you get started with contributing to the project, whether you're fixing bugs, adding features, improving documentation, or helping in other ways.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read it before contributing.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic knowledge of Python and authentication systems
- Familiarity with Evrmore blockchain (helpful but not required)

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/evrmore-authentication.git
   cd evrmore-authentication
   ```
3. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip3 install -e ".[dev]"  # Install package in development mode with dev dependencies
   ```
4. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Development Workflow

### Branching Strategy

We use a simplified Git workflow:

- `main` branch is the stable branch with released code
- Feature branches are created from `main` and merged back via pull requests

### Creating a Branch

Create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Use a descriptive name that reflects the purpose of your changes.

### Making Changes

1. Make your changes to the codebase
2. Write or update tests to cover your changes
3. Run the tests to ensure they pass:
   ```bash
   python3 -m pytest
   ```
4. Run the linter to ensure code quality:
   ```bash
   flake8 evrmore_authentication
   ```
5. Format your code:
   ```bash
   black evrmore_authentication
   ```

### Committing Changes

Follow these guidelines for commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

Example:
```
Add OAuth token refresh functionality

- Implement refresh token generation
- Add token refresh endpoint
- Update documentation

Fixes #123
```

### Submitting a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
2. Go to the original repository on GitHub and create a pull request
3. Fill in the pull request template with details about your changes
4. Wait for a maintainer to review your pull request
5. Address any feedback and make necessary changes
6. Once approved, your pull request will be merged

## Pull Request Guidelines

A good pull request:

- Focuses on a single feature or bug fix
- Includes tests for new functionality or bug fixes
- Updates documentation to reflect changes
- Follows the code style of the project
- Has a clear and descriptive title and description
- Passes all CI checks

## Testing

Please refer to the [Testing Guide](testing.md) for detailed information on writing and running tests.

### Running Tests

```bash
# Run all tests
python3 -m pytest

# Run tests with coverage
python3 -m pytest --cov=evrmore_authentication

# Run specific tests
python3 -m pytest evrmore_authentication/tests/unit/test_auth.py
```

## Documentation

Good documentation is crucial for the project. Please update the documentation when you make changes to the code.

### Documentation Structure

- API reference documentation is in the `docs/api-reference/` directory
- User guides are in the `docs/user-guide/` directory
- Examples are in the `docs/examples/` directory
- Development guides are in the `docs/development/` directory

### Building Documentation

We use MkDocs for documentation. To build and preview the documentation:

```bash
# Install MkDocs and dependencies
pip3 install mkdocs mkdocs-material

# Build and serve documentation locally
mkdocs serve
```

Then open your browser to `http://localhost:8000` to preview the documentation.

## Code Style

We follow the [Black](https://black.readthedocs.io/) code style with a line length of 88 characters. We also use [isort](https://pycqa.github.io/isort/) for import sorting and [flake8](https://flake8.pycqa.org/) for linting.

### Automatic Formatting

```bash
# Format code with Black
black evrmore_authentication

# Sort imports with isort
isort evrmore_authentication
```

### Linting

```bash
# Run flake8
flake8 evrmore_authentication
```

## Security Considerations

Security is a top priority for this project. Please follow these guidelines:

- Never commit sensitive information (private keys, passwords, etc.)
- Use secure cryptographic practices
- Validate all user inputs
- Follow the principle of least privilege
- Report security vulnerabilities privately (see [Security Policy](security.md))

## Feature Requests and Bug Reports

If you have a feature request or have found a bug, please open an issue on GitHub. Use the appropriate issue template and provide as much detail as possible.

### Issue Templates

- Bug Report: For reporting bugs or unexpected behavior
- Feature Request: For suggesting new features or improvements
- Documentation Issue: For reporting issues with documentation

## Community

Join our community to get help, share ideas, and collaborate:

- GitHub Discussions: For general questions and discussions
- Issue Tracker: For bug reports and feature requests
- Discord: [Join our Discord server](https://discord.gg/manticore)

## Release Process

The release process is handled by the maintainers. If you're interested in the release process, please refer to the [Release Guide](release-process.md).

## Acknowledgments

Contributors will be acknowledged in the project's README and release notes. We appreciate all contributions, big or small!

## License

By contributing to this project, you agree that your contributions will be licensed under the project's license. See the [LICENSE](../../LICENSE) file for details.

## Contact

If you have any questions or need help, you can reach out to the maintainers:

- Email: dev@manticore.technology
- GitHub: [@manticoretechnologies](https://github.com/manticoretechnologies)

Thank you for contributing to Evrmore Authentication! 