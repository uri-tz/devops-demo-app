from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    ldap_uri: str = Field(..., env="LDAP_URI")
    ldap_bind_dn: str = Field(..., env="LDAP_BIND_DN")
    ldap_bind_password: str = Field(..., env="LDAP_BIND_PASSWORD")
    ldap_base_dn: str = Field(..., env="LDAP_BASE_DN")
    ldap_mail_attr: str = Field("mail", env="LDAP_MAIL_ATTR")
    ldap_display_attr: str = Field("displayName", env="LDAP_DISPLAY_ATTR")
    admin_users: List[str] = Field(default_factory=list, env="ADMIN_USERS")
    admin_group_dn: Optional[str] = Field(default=None, env="ADMIN_GROUP_DN")
    keys_json_path: Path = Field(Path("/etc/vllm/keys.json"), env="KEYS_JSON_PATH")
    key_default_ttl_days: int = Field(30, env="KEY_DEFAULT_TTL_DAYS")
    session_secret: str = Field(..., env="SESSION_SECRET")
    https_only: bool = Field(True, env="HTTPS_ONLY")
    audit_log_path: Path = Field(Path("/var/log/vllm-keyportal/audit.log"), env="AUDIT_LOG_PATH")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("admin_users", pre=True)
    def _split_admin_users(cls, value: str | List[str]) -> List[str]:
        if isinstance(value, list):
            return [v.strip() for v in value if v.strip()]
        if not value:
            return []
        return [part.strip() for part in value.split(",") if part.strip()]

    @validator("key_default_ttl_days")
    def _validate_ttl(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("KEY_DEFAULT_TTL_DAYS must be positive")
        return value

    @validator("admin_group_dn")
    def _empty_string_to_none(cls, value: Optional[str]) -> Optional[str]:
        if value and value.strip():
            return value.strip()
        return None

    @validator("keys_json_path", "audit_log_path")
    def _expand_paths(cls, value: Path) -> Path:
        return Path(os.path.expanduser(str(value)))


@lru_cache()
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]
