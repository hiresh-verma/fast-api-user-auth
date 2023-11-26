import random
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, constr, Field, NonNegativeInt


class UserBaseSchema(BaseModel):
    name: str
    email: str
    photo: str
    role: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        orm_mode = True


class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=8)
    passwordConfirm: str
    verified: bool = False


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserResponseSchema(UserBaseSchema):
    id: str
    pass


class UserResponse(BaseModel):
    status: str
    user: UserResponseSchema


class OtpSchema(BaseModel):
    email: str
    otp: int = Field(default_factory=lambda: random.randint(10000, 99999))
    retries: int = 0
    submission_attempts: int = 0
    unsuccessful_attempts: int = 0
    verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime | None = None
    retry_after: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=5))
    expires_after: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(hours=12))
