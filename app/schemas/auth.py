import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class Credentials(BaseModel):
    # A lookup key, not a new address: corporate domains such as .local must still sign in.
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=128)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
