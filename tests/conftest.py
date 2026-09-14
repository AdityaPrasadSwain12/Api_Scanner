import os
from pathlib import Path

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test-api-scanner.sqlite3"
os.environ["SCANNER_API_KEY"] = "test-api-key"
os.environ["SECRET_ENCRYPTION_KEY"] = "NQ4M5lY8yl5wE9bG6vRCcQ5Rk4j1g5HVFFOS5iQlJ0k="
os.environ["ALLOWED_TARGETS"] = "api.example.test,localhost,127.0.0.1"
os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
os.environ["DASHBOARD_AUTH_MODE"] = "api_key"
os.environ["TASK_ALWAYS_EAGER"] = "false"
os.environ["REPORT_DIRECTORY"] = "./test-reports"

import pytest
from fastapi.testclient import TestClient

from app.db import SessionLocal, create_schema, engine
from app.main import app
from app.models.database import Base


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(engine)
    create_schema()
    yield


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


@pytest.fixture
def api_headers():
    return {"X-API-Key": "test-api-key", "X-Actor": "pytest"}


def pytest_sessionfinish(session, exitstatus):
    Base.metadata.drop_all(engine)
    engine.dispose()
    path = Path("test-api-scanner.sqlite3")
    if path.exists():
        path.unlink()
