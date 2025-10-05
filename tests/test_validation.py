import pytest

from app import auth
from app.models import UserInfo


@pytest.fixture
def admin_client(app_client, monkeypatch: pytest.MonkeyPatch):
    def fake_auth(self, username: str, password: str):
        return UserInfo(username="admin", email="admin@example.com", display_name="Admin")

    def fake_is_admin(self, user: UserInfo) -> bool:
        return True

    monkeypatch.setattr(auth.LDAPClient, "authenticate", fake_auth, raising=False)
    monkeypatch.setattr(auth.LDAPClient, "is_admin", fake_is_admin, raising=False)
    response = app_client.post("/auth/login", json={"username": "admin", "password": "pass"})
    assert response.status_code == 200
    return app_client


def test_invalid_app_name(admin_client):
    response = admin_client.post("/admin/app-keys", json={"name": "!bad", "key": "abcd1234"})
    assert response.status_code == 422


def test_duplicate_app_name(admin_client):
    first = admin_client.post("/admin/app-keys", json={"name": "doc", "key": "abcd1234"})
    assert first.status_code == 200
    dup = admin_client.post("/admin/app-keys", json={"name": "doc", "key": "abcd1234"})
    assert dup.status_code == 409
    assert dup.json()["detail"] == "App key already exists"
