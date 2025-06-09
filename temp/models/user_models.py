from pydantic import BaseModel, EmailStr
from typing import Optional

# User creation (sign up) model
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

# User login model
class UserLogin(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: str

    # Custom validation to ensure either username or email is provided
    def validate_login_fields(self):
        if not self.username and not self.email:
            raise ValueError("Either username or email must be provided for login.")
        return self
