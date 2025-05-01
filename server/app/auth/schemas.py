from typing import Optional, Any, Union
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    """Schema for creating a new user"""

    name: str = Field(..., example="John Doe")
    email: EmailStr = Field(..., example="john@example.com")
    password: str = Field(..., example="strongpassword123", min_length=8)


class UserLogin(BaseModel):
    """Schema for user login"""

    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Schema for user response"""

    id: UUID
    name: str
    email: EmailStr

    model_config = {"from_attributes": True}


class Token(BaseModel):
    """Schema for authentication token"""

    access_token: str
    token_type: str
    user: UserResponse


class TokenPayload(BaseModel):
    """Schema for token payload"""

    sub: Optional[str] = None


class ChangePassword(BaseModel):
    """Schema for changing password"""

    current_password: str
    new_password: str = Field(..., min_length=8)
