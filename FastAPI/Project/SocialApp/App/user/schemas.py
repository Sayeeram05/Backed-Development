from pydantic import BaseModel, EmailStr, ConfigDict
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str  # str not EmailStr — avoids re-validating DB data on read
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
