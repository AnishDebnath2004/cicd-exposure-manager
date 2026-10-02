import re
from datetime import datetime
from typing import Optional, List, Literal, Any, Dict
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class UserSignupRequest(BaseModel):
    """Payload for user registration."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (at least 8 characters)")
    full_name: Optional[str] = Field(None, description="User full name or display name")
    organization: Optional[str] = Field(None, description="Organization or team name")
    role: Literal["developer", "user", "admin"] = Field("developer", description="User role: 'developer', 'user', or 'admin'")
    preferred_domain: Optional[str] = Field("domain_01", description="Preferred development domain (e.g. domain_01, domain_02, domain_03)")

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
    required_role: Optional[Literal["admin", "developer", "user"]] = Field(
        None, description="Enforce that the authenticating account matches this specific role"
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v


class UserResponse(BaseModel):
    """Public user profile returned to client."""
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    full_name: Optional[str] = None
    organization: Optional[str] = None
    role: str = "developer"
    preferred_domain: Optional[str] = "domain_01"
    token_version: int = 1
    created_at: datetime
    last_login_at: Optional[datetime] = None
    scan_count: int = 0
    mfa_enabled: bool = False


class AuthTokenResponse(BaseModel):
    """Response returned upon successful login/signup, or when MFA challenge is required."""
    model_config = ConfigDict(extra="ignore")
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in_seconds: int = 86400 * 7  # 7 days
    user: Optional[UserResponse] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    message: Optional[str] = None


class UserProfileUpdateRequest(BaseModel):
    """Payload for updating user profile information."""
    full_name: Optional[str] = Field(None, description="User full or display name")
    organization: Optional[str] = Field(None, description="Organization or team name")
    preferred_domain: Optional[str] = Field(None, description="Preferred development domain")


class PasswordChangeRequest(BaseModel):
    """Payload for changing password."""
    current_password: str = Field(..., description="Existing account password")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")


class UserRoleUpdateRequest(BaseModel):
    """Payload for updating a user's role and domain delegation (Admin only)."""
    role: Literal["admin", "developer", "user"] = Field(..., description="Target role: 'admin', 'developer', or 'user'")
    preferred_domain: Optional[str] = Field(None, description="Preferred domain delegation: 'domain_01', 'domain_02', or 'domain_03'")


class AdminCreateUserRequest(BaseModel):
    """Payload for an admin provisioning a new user/admin directly."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Initial account password")
    full_name: Optional[str] = Field(None, description="User full name")
    organization: Optional[str] = Field(None, description="Organization or team name")
    role: Literal["admin", "developer", "user"] = Field("admin", description="Assigned role: 'admin', 'developer', or 'user'")
    preferred_domain: Optional[str] = Field("domain_01", description="Preferred domain")

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


# ==============================================================
# Multi-Factor Authentication (MFA / 2FA) Schemas
# ==============================================================
class MfaSetupResponse(BaseModel):
    """Response returned when initiating TOTP MFA enrollment."""
    model_config = ConfigDict(extra="ignore")
    secret: str = Field(..., description="Base32 TOTP secret key for manual entry")
    otpauth_uri: str = Field(..., description="Standard otpauth:// URI for authenticator apps")
    totp_uri: Optional[str] = Field(None, description="Standard otpauth:// URI for authenticator apps (alias for frontend compatibility)")
    recovery_codes: List[str] = Field(..., description="List of single-use emergency recovery codes")

    @model_validator(mode="before")
    @classmethod
    def populate_uri_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            uri = data.get("otpauth_uri") or data.get("totp_uri")
            if uri:
                data["otpauth_uri"] = uri
                data["totp_uri"] = uri
        return data


class MfaEnableRequest(BaseModel):
    """Payload to confirm TOTP code and enable MFA."""
    secret: str = Field(..., description="The base32 secret provided during setup")
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP verification code from authenticator app")
    recovery_codes: Optional[List[str]] = Field(default=None, description="Recovery codes provided during setup")


class MfaDisableRequest(BaseModel):
    """Payload to disable MFA for an account."""
    password: str = Field(..., description="Current account password for confirmation")
    code: Optional[str] = Field(None, description="6-digit TOTP code or backup recovery code")


class MfaVerifyRequest(BaseModel):
    """Payload to verify MFA challenge during login."""
    mfa_token: str = Field(..., description="Temporary signed challenge token received during initial login")
    code: str = Field(..., description="6-digit TOTP code or 8-character recovery code")


class MfaStatusResponse(BaseModel):
    """MFA status and governance statistics for admin section."""
    mfa_enabled: bool = False
    recovery_codes_remaining: int = 0
    enforce_admin_mfa: bool = False
    enforce_all_users_mfa: bool = False
    total_users_enrolled: int = 0
    total_users_count: int = 0
    adoption_percentage: float = 0.0
    metrics: Optional[Dict[str, Any]] = None


class MfaPolicyUpdateRequest(BaseModel):
    """Admin payload to update platform-wide MFA policies."""
    enforce_admin_mfa: bool = Field(False, description="Require all administrators to enroll in MFA")
    enforce_all_users_mfa: bool = Field(False, description="Require all developers and users to enroll in MFA")


class UserScansResponse(BaseModel):
    """Scans performed by a specific user for admin inspection."""
    user_id: str
    email: str
    full_name: Optional[str] = None
    total_scans: int
    scans: List[Any] = []



