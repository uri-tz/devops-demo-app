from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import create_app


@pytest.fixture(autouse=True)
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    keys_path = tmp_path / "keys.json"
    audit_log = tmp_path / "audit.log"
    env = {
        "LDAP_URI": "ldap://test",
        "LDAP_BIND_DN": "CN=svc,DC=example,DC=com",
        "LDAP_BIND_PASSWORD": "secret",
        "LDAP_BASE_DN": "DC=example,DC=com",
        "LDAP_MAIL_ATTR": "mail",
        "LDAP_DISPLAY_ATTR": "displayName",
        "ADMIN_USERS": "admin",
        "KEYS_JSON_PATH": str(keys_path),
        "KEY_DEFAULT_TTL_DAYS": "30",
        "SESSION_SECRET": "test-secret",
        "HTTPS_ONLY": "false",
        "AUDIT_LOG_PATH": str(audit_log),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    settings = Settings()
    return settings


@pytest.fixture
def app_client(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    app = create_app(settings)
    with TestClient(app) as client:
        yield client
