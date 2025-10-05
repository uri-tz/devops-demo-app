from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Optional

from ldap3 import ALL, Connection, NTLM, Server, SUBTREE

from .config import Settings
from .models import UserInfo

logger = logging.getLogger(__name__)


def _build_server(settings: Settings) -> Server:
    return Server(settings.ldap_uri, get_info=ALL)


@contextmanager
def _service_connection(settings: Settings):
    server = _build_server(settings)
    conn = Connection(
        server,
        user=settings.ldap_bind_dn,
        password=settings.ldap_bind_password,
        auto_bind=True,
    )
    try:
        yield conn
    finally:
        conn.unbind()


class LDAPClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def authenticate(self, username: str, password: str) -> Optional[UserInfo]:
        username = username.strip()
        if not username or not password:
            return None
        server = _build_server(self.settings)
        user_dn = f"{username}@{self._domain_from_bind()}"
        try:
            with Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True) as conn:
                logger.debug("LDAP bind successful for %s", username)
                return self._fetch_user_info(conn, username)
        except Exception:  # noqa: BLE001
            logger.info("LDAP bind failed for %s", username)
            return None

    def is_admin(self, user: UserInfo) -> bool:
        username_lower = user.username.lower()
        if username_lower in {u.lower() for u in self.settings.admin_users}:
            return True
        if not self.settings.admin_group_dn:
            return False
        try:
            with _service_connection(self.settings) as conn:
                conn.search(
                    search_base=self.settings.admin_group_dn,
                    search_filter="(objectClass=group)",
                    search_scope=SUBTREE,
                    attributes=["member"],
                )
                if not conn.entries:
                    return False
                members = conn.entries[0].member.values if hasattr(conn.entries[0], "member") else []
                username_dn = self._build_user_dn(username_lower)
                return any(member.lower() == username_dn.lower() for member in members)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to check admin group membership", exc_info=True)
            return username_lower in {u.lower() for u in self.settings.admin_users}

    def _fetch_user_info(self, conn: Connection, username: str) -> Optional[UserInfo]:
        search_filter = f"(sAMAccountName={username})"
        conn.search(
            search_base=self.settings.ldap_base_dn,
            search_filter=search_filter,
            attributes=[
                "sAMAccountName",
                self.settings.ldap_mail_attr,
                self.settings.ldap_display_attr,
            ],
        )
        if not conn.entries:
            logger.warning("LDAP user %s not found after successful bind", username)
            return None
        entry = conn.entries[0]
        email = getattr(entry, self.settings.ldap_mail_attr, None)
        display_name = getattr(entry, self.settings.ldap_display_attr, None)
        return UserInfo(
            username=username,
            email=(email.value if email else None),
            display_name=(display_name.value if display_name else None),
        )

    def _build_user_dn(self, username: str) -> str:
        return f"CN={username},{self.settings.ldap_base_dn}"

    def _domain_from_bind(self) -> str:
        if "@" in self.settings.ldap_bind_dn:
            return self.settings.ldap_bind_dn.split("@", 1)[1]
        parts = [p.split("=")[1] for p in self.settings.ldap_bind_dn.split(",") if p.strip().startswith("DC=")]
        return ".".join(parts)
