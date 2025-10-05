from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from pydantic import BaseModel, EmailStr, Field, validator


class KeyEntry(BaseModel):
    key: str
    created_at: datetime
    expires_at: Optional[datetime] = None

    @validator("created_at", "expires_at", pre=True)
    def _parse_datetime(cls, value):
        if value is None:
            return value
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        }


class KeysDocument(BaseModel):
    gpt: Dict[str, KeyEntry] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserInfo(BaseModel):
    username: str
    email: Optional[EmailStr]
    display_name: Optional[str]

    @property
    def identifier(self) -> str:
        if self.email:
            return self.email.lower()
        if self.display_name:
            return self.display_name
        return self.username


class AuthenticatedUser(BaseModel):
    username: str
    email: Optional[EmailStr]
    display_name: Optional[str]
    is_admin: bool

    @property
    def identifier(self) -> str:
        if self.email:
            return self.email.lower()
        if self.display_name:
            return self.display_name
        return self.username


class AppKeyRequest(BaseModel):
    name: str = Field(..., regex=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,62}$")
    key: Optional[str] = Field(default=None, min_length=8)

    @validator("name")
    def _lower(cls, value: str) -> str:
        return value.lower()


class AppKeyResponse(BaseModel):
    name: str
    key: str
    created_at: datetime
    expires_at: Optional[datetime]


class PersonalKeyResponse(BaseModel):
    subject: str
    key: str
    created_at: datetime
    expires_at: datetime
