
from fastapi.testclient import TestClient
from app.main import app

# Create a test client for the ProWork API
client = TestClient(app)


def test_root_endpoint():
    """Check that the root endpoint works."""
    response = client.get("/")

    assert response.status_code == 200


def test_health_endpoint():
    """Check that the health endpoint works."""
    response = client.get("/health")

    assert response.status_code == 200


def test_tasks_requires_authentication():
    """Check that tasks cannot be accessed without logging in."""
    response = client.get("/tasks")

    assert response.status_code == 401
