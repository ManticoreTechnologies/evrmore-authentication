# Evrmore Authentication Test Suite

This directory contains the test suite for the Evrmore Authentication system. The tests are organized into different categories to provide comprehensive coverage of the system's functionality.

## Test Structure

- **Unit Tests**: Located in the `unit/` directory, these tests verify the correctness of individual components and functions.
- **Integration Tests**: Located in the `integration/` directory, these tests verify that different components work together correctly.
- **End-to-End Tests**: Located in the `e2e/` directory, these tests verify complete workflows from start to finish.

## Running Tests

To run the entire test suite:

```bash
python3 -m pytest
```

To run a specific test file:

```bash
python3 -m pytest evrmore_authentication/tests/unit/test_auth.py
```

To run tests with verbose output:

```bash
python3 -m pytest -v
```

To run tests with code coverage:

```bash
python3 -m pytest --cov=evrmore_authentication
```

## Configuration

The test suite is configured using `pytest.ini` at the root of the project. This configuration includes settings for:

- Test paths
- File patterns
- Coverage reporting
- Warning suppression

## Fixtures

Common fixtures used across multiple tests are defined in `conftest.py`. These include:

- `auth`: An instance of `EvrmoreAuth` with debug mode enabled
- `test_user`: A sample user for testing
- `test_challenge`: A sample challenge for testing
- `test_signature`: A sample signature for testing
- `test_session`: A sample user session for testing
- `patch_sqlite_connection`: A fixture that sets up an in-memory SQLite database for testing

## Writing New Tests

When writing new tests, follow these guidelines:

1. Put unit tests in the `unit/` directory
2. Put integration tests in the `integration/` directory
3. Put end-to-end tests in the `e2e/` directory
4. Use fixtures from `conftest.py` where appropriate
5. Mock external dependencies to avoid network requests and database operations
6. Follow the naming convention: `test_*.py` for test files and `test_*` for test functions
7. Write clear assertions that test one thing at a time

## Continuous Integration

The test suite is run automatically as part of the CI pipeline whenever changes are pushed to the repository. All tests must pass before changes can be merged. 