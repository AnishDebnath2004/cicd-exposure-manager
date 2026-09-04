import re
from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, field_validator

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class UserSignupRequest(BaseModel):
    """Payload for user registration."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (at least 8 characters)")
    full_name: Optional[str] = Field(None, description="User full name or display name")
    organization: Optional[str] = Field(None, description="Organization or team name")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v


class UserLoginRequest(BaseModel):
    """Payload for user login."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v


class UserResponse(BaseModel):
    """Public user profile returned to client."""
    id: str
    email: str
    full_name: Optional[str] = None
    organization: Optional[str] = None
    role: str = "developer"
    token_version: int = 1
    created_at: datetime
    last_login_at: Optional[datetime] = None


class AuthTokenResponse(BaseModel):
    """Response returned upon successful login or signup."""
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int = 86400 * 7  # 7 days
    user: UserResponse


class UserProfileUpdateRequest(BaseModel):
    """Payload for updating user profile information."""
    full_name: Optional[str] = Field(None, description="User full or display name")
    organization: Optional[str] = Field(None, description="Organization or team name")


class PasswordChangeRequest(BaseModel):
    """Payload for changing password."""
    current_password: str = Field(..., description="Existing account password")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")


class UserRoleUpdateRequest(BaseModel):
    """Payload for updating a user's role (Admin only)."""
    role: Literal["admin", "developer"] = Field(..., description="Target role: 'admin' or 'developer'")


class AdminCreateUserRequest(BaseModel):
    """Payload for an admin provisioning a new user/admin directly."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Initial account password")
    full_name: Optional[str] = Field(None, description="User full name")
    organization: Optional[str] = Field(None, description="Organization or team name")
    role: Literal["admin", "developer"] = Field("admin", description="Assigned role: 'admin' or 'developer'")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v


class UserListResponse(BaseModel):
    """Admin response containing list of all registered users."""
    total: int
    users: List[UserResponse]


