from contextlib import contextmanager

import pytest

from app.config import Settings
from app.ldap_client import LDAPClient
from app.models import UserInfo


def test_admin_users_only(settings: Settings):
    client = LDAPClient(settings)
    user = UserInfo(username="admin", email="admin@example.com", display_name="Admin")
    assert client.is_admin(user) is True

    non_admin = UserInfo(username="bob", email="bob@example.com", display_name="Bob")
    assert client.is_admin(non_admin) is False


def test_admin_group_lookup(monkeypatch: pytest.MonkeyPatch, settings: Settings):
    settings.admin_group_dn = "CN=Admins,DC=example,DC=com"
    client = LDAPClient(settings)

    class FakeEntry:
        class Member:
            values = ["CN=bob,DC=example,DC=com"]

        member = Member()

    class FakeConnection:
        entries = [FakeEntry()]

        def search(self, *args, **kwargs):
            return True

    @contextmanager
    def fake_service_connection(settings):
        yield FakeConnection()

    monkeypatch.setattr("app.ldap_client._service_connection", fake_service_connection)

    user = UserInfo(username="bob", email="bob@example.com", display_name="Bob")
    assert client.is_admin(user) is True


def test_admin_group_lookup_failure(monkeypatch: pytest.MonkeyPatch, settings: Settings):
    settings.admin_group_dn = "CN=Admins,DC=example,DC=com"
    client = LDAPClient(settings)

    @contextmanager
    def fake_service_connection(settings):
        raise RuntimeError("LDAP down")
        yield

    monkeypatch.setattr("app.ldap_client._service_connection", fake_service_connection)

    user = UserInfo(username="alice", email="alice@example.com", display_name="Alice")
    # Falls back to admin_users list which contains only "admin"
    assert client.is_admin(user) is False
