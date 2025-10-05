from app import auth
from app.models import UserInfo


def test_security_headers(app_client, monkeypatch):
    # ensure login to avoid redirect loops
    monkeypatch.setattr(auth.LDAPClient, "authenticate", lambda self, u, p: UserInfo(username="alice", email="a@b", display_name="A"), raising=False)
    monkeypatch.setattr(auth.LDAPClient, "is_admin", lambda self, user: False, raising=False)
    app_client.post("/auth/login", json={"username": "alice", "password": "pass"})
    response = app_client.get("/")
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
