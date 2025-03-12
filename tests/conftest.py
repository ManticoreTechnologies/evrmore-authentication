import os
import pytest
import tempfile
from evrmore_authentication import EvrmoreAuth

@pytest.fixture
def temp_db_path():
    """Create a temporary database file path."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    os.unlink(path)

@pytest.fixture
def auth(temp_db_path):
    """Create an EvrmoreAuth instance with a temporary database."""
    os.environ['DB_URL'] = f'sqlite:///{temp_db_path}'
    auth = EvrmoreAuth()
    yield auth 