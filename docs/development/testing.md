# Testing Guide

This guide covers the testing approach for the Evrmore Authentication system, including unit tests, integration tests, and how to run and extend the test suite.

## Testing Philosophy

The Evrmore Authentication system follows these testing principles:

1. **Test-Driven Development**: Critical components are developed using TDD where possible.
2. **Comprehensive Coverage**: Aim for high test coverage, especially for security-critical components.
3. **Isolation**: Unit tests should be isolated and not depend on external services.
4. **Realistic Scenarios**: Integration tests should simulate real-world usage patterns.

## Test Structure

The tests are organized in the following structure:

```
evrmore_authentication/tests/
├── unit/                 # Unit tests
│   ├── test_auth.py      # Tests for core authentication functionality
│   ├── test_crypto.py    # Tests for cryptographic functions
│   ├── test_models.py    # Tests for data models
│   └── test_utils.py     # Tests for utility functions
├── integration/          # Integration tests
│   ├── test_api.py       # Tests for API endpoints
│   └── test_oauth.py     # Tests for OAuth functionality
└── conftest.py           # Pytest fixtures and configuration
```

## Running Tests

### Prerequisites

Before running tests, ensure you have the required dependencies:

```bash
pip3 install pytest pytest-cov pytest-mock
```

### Running All Tests

To run all tests:

```bash
python3 -m pytest
```

### Running Specific Test Categories

To run only unit tests:

```bash
python3 -m pytest evrmore_authentication/tests/unit/
```

To run only integration tests:

```bash
python3 -m pytest evrmore_authentication/tests/integration/
```

### Running a Specific Test File

To run tests from a specific file:

```bash
python3 -m pytest evrmore_authentication/tests/unit/test_auth.py
```

### Running a Specific Test

To run a specific test function:

```bash
python3 -m pytest evrmore_authentication/tests/unit/test_auth.py::test_generate_challenge
```

### Test Coverage

To generate a test coverage report:

```bash
python3 -m pytest --cov=evrmore_authentication
```

For a detailed HTML coverage report:

```bash
python3 -m pytest --cov=evrmore_authentication --cov-report=html
```

This will create a `htmlcov` directory with an HTML report that you can open in your browser.

## Writing Tests

### Unit Tests

Unit tests should focus on testing individual functions or methods in isolation. Use mocks to avoid dependencies on external services or other components.

Example of a unit test:

```python
def test_verify_signature(mocker):
    # Arrange
    mock_verify = mocker.patch('evrmore_authentication.crypto.verify_message', return_value=True)
    auth = EvrmoreAuth()
    address = "EXaMPLeEvRMoReAddResS"
    message = "Test message"
    signature = "TestSignature"
    
    # Act
    result = auth.verify_signature(address, message, signature)
    
    # Assert
    assert result is True
    mock_verify.assert_called_once_with(address, message, signature)
```

### Integration Tests

Integration tests should test the interaction between multiple components or the system as a whole. These tests may require more setup but provide confidence that the system works correctly in real-world scenarios.

Example of an integration test:

```python
def test_authentication_flow():
    # Arrange
    auth = EvrmoreAuth()
    address, private_key = create_wallet()
    
    # Act
    # 1. Generate a challenge
    challenge = auth.generate_challenge(address)
    
    # 2. Sign the challenge
    signature = sign_message(private_key, challenge)
    
    # 3. Authenticate with the signature
    session = auth.authenticate(address, challenge, signature)
    
    # Assert
    assert session is not None
    assert session.user_id is not None
    assert session.evrmore_address == address
    assert session.token is not None
    
    # 4. Validate the token
    token_data = auth.validate_token(session.token)
    assert token_data is not None
    assert token_data.get('sub') == session.user_id
    assert token_data.get('evr_address') == address
```

### Test Fixtures

Pytest fixtures are used to set up test dependencies and can be defined in `conftest.py` or in individual test files.

Example of fixtures in `conftest.py`:

```python
import pytest
from evrmore_authentication import EvrmoreAuth
from evrmore_authentication.crypto import create_wallet

@pytest.fixture
def auth():
    """Return an initialized EvrmoreAuth instance."""
    return EvrmoreAuth(jwt_secret="test-secret", debug=True)

@pytest.fixture
def test_wallet():
    """Create a test wallet for testing."""
    address, private_key = create_wallet()
    return {"address": address, "private_key": private_key}

@pytest.fixture
def authenticated_user(auth, test_wallet):
    """Return an authenticated user session."""
    address = test_wallet["address"]
    private_key = test_wallet["private_key"]
    
    # Generate a challenge
    challenge = auth.generate_challenge(address)
    
    # Sign the challenge
    signature = sign_message(private_key, challenge)
    
    # Authenticate
    session = auth.authenticate(address, challenge, signature)
    
    return {
        "session": session,
        "address": address,
        "challenge": challenge,
        "signature": signature
    }
```

## Mocking

The `pytest-mock` plugin provides a `mocker` fixture that can be used to create mock objects and patch functions.

Example of mocking:

```python
def test_get_user_by_token(mocker):
    # Arrange
    mock_validate = mocker.patch('evrmore_authentication.auth.EvrmoreAuth.validate_token')
    mock_validate.return_value = {"sub": "test-user-id", "evr_address": "test-address"}
    
    mock_get_user = mocker.patch('evrmore_authentication.models.User.get_by_id')
    mock_user = mocker.MagicMock()
    mock_user.id = "test-user-id"
    mock_get_user.return_value = mock_user
    
    auth = EvrmoreAuth()
    
    # Act
    user = auth.get_user_by_token("test-token")
    
    # Assert
    assert user is mock_user
    mock_validate.assert_called_once_with("test-token")
    mock_get_user.assert_called_once_with("test-user-id")
```

## Testing API Endpoints

API endpoints can be tested using FastAPI's `TestClient`.

Example of testing an API endpoint:

```python
from fastapi.testclient import TestClient
from evrmore_authentication.api import app

client = TestClient(app)

def test_generate_challenge_endpoint():
    # Arrange
    test_address = "EXaMPLeEvRMoReAddResS"
    
    # Act
    response = client.post(
        "/auth/challenge",
        json={"evrmore_address": test_address}
    )
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert "challenge" in data
    assert data["status"] == "success"
```

## Testing OAuth Functionality

OAuth functionality requires more complex setup and interaction between client and server.

Example of testing OAuth authorization:

```python
def test_oauth_authorization_flow(mocker):
    # Mock the authentication
    mock_auth = mocker.patch('evrmore_authentication.oauth.authenticate_user')
    mock_auth.return_value = {"user_id": "test-user-id", "evrmore_address": "test-address"}
    
    # Mock the client validation
    mock_client = mocker.patch('evrmore_authentication.oauth.get_client_by_id')
    mock_client.return_value = {
        "id": "test-client-id",
        "name": "Test Client",
        "redirect_uris": ["http://localhost/callback"],
        "scopes": ["profile"]
    }
    
    # Create a test client
    client = TestClient(app)
    
    # Act - Initiate the authorization flow
    response = client.get(
        "/oauth/auth",
        params={
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost/callback",
            "response_type": "code",
            "scope": "profile",
            "state": "test-state"
        }
    )
    
    # Assert - Should redirect to login page
    assert response.status_code == 302
    assert "/oauth/login" in response.headers["location"]
    
    # Act - Simulate successful login and authorization
    response = client.post(
        "/oauth/login",
        json={
            "evrmore_address": "test-address",
            "challenge": "test-challenge",
            "signature": "test-signature",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost/callback",
            "scope": "profile",
            "state": "test-state"
        }
    )
    
    # Assert - Should redirect to the client with an authorization code
    assert response.status_code == 302
    redirect_uri = response.headers["location"]
    assert "http://localhost/callback" in redirect_uri
    assert "code=" in redirect_uri
    assert "state=test-state" in redirect_uri
```

## Continuous Integration

Tests are automatically run in the CI pipeline on every push and pull request. The CI configuration is defined in the `.github/workflows/tests.yml` file.

## Test Environment

Tests use an in-memory SQLite database by default to avoid affecting any production data. The database is created fresh for each test run and destroyed afterward.

To configure the test environment, you can set environment variables or modify the `conftest.py` file.

## Troubleshooting Tests

### Common Issues

1. **Database Errors**: Ensure the test database is properly configured and accessible.
2. **Import Errors**: Check that all required dependencies are installed.
3. **Mock Issues**: Verify that mocks are correctly set up and returning the expected values.
4. **Fixture Errors**: Ensure fixtures are correctly defined and dependencies are resolved.

### Debugging Tests

To run tests with more verbose output:

```bash
python3 -m pytest -v
```

To enable print statements during tests:

```bash
python3 -m pytest -v --capture=no
```

To debug a specific test with a debugger:

```bash
python3 -m pytest --pdb evrmore_authentication/tests/unit/test_auth.py::test_generate_challenge
```

## Best Practices

1. **Keep Tests Fast**: Tests should run quickly to encourage frequent testing.
2. **Independent Tests**: Tests should not depend on each other or run in a specific order.
3. **Clear Assertions**: Make assertions clear and specific to what is being tested.
4. **Test Edge Cases**: Include tests for edge cases and error conditions.
5. **Maintain Tests**: Update tests when the code changes to prevent test debt.

## Contributing Tests

When contributing new features or bug fixes, please include appropriate tests. Follow these guidelines:

1. Write tests for new functionality before implementing it (TDD).
2. Add regression tests for bug fixes to prevent the bug from recurring.
3. Follow the existing test structure and naming conventions.
4. Ensure all tests pass before submitting a pull request.

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [FastAPI Testing Documentation](https://fastapi.tiangolo.com/tutorial/testing/)
- [Python Mock Object Library](https://docs.python.org/3/library/unittest.mock.html) 