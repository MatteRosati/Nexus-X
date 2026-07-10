import os
from pathlib import Path

TEST_DB = Path("/tmp/easm_test.db")
TEST_DB.unlink(missing_ok=True)
os.environ["APP_API_KEY"] = "test-api-key-with-more-than-thirty-two-characters"
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["EASM_ALLOWED_DOMAINS"] = "example.com"
os.environ["CENSYS_ENABLED"] = "false"
os.environ["TRUSTED_HOSTS"] = "testserver,localhost,127.0.0.1"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"X-API-Key": os.environ["APP_API_KEY"]}
