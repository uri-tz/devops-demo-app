import pytest

from app import auth
from app.models import UserInfo


@pytest.fixture(autouse=True)
def mock_ldap(monkeypatch: pytest.MonkeyPatch):
    def fake_auth(self, username: str, password: str) -> UserInfo | None:
        if username == "alice" and password == "pass":
            return UserInfo(username=username, email="alice@example.com", display_name="Alice")
        return None

    def fake_is_admin(self, user: UserInfo) -> bool:
        return user.username == "admin"

    monkeypatch.setattr(auth.LDAPClient, "authenticate", fake_auth, raising=False)
    monkeypatch.setattr(auth.LDAPClient, "is_admin", fake_is_admin, raising=False)
    yield


def test_login_success(app_client):
    response = app_client.post("/auth/login", json={"username": "alice", "password": "pass"})
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice"
    assert body["is_admin"] is False
    assert "vllm_session" in response.cookies


def test_login_failure(app_client):
    response = app_client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"
