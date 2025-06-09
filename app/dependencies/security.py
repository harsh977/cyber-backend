from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
import time
import os
from dotenv import load_dotenv

# OAuth2 password bearer for extracting the token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

def verify_token(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Decodes the JWT token and returns the payload (user data).
    """
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Extract user data
        first_name = payload.get("first_name")
        last_name = payload.get("last_name")
        email = payload.get("email")
        role = payload.get("role")
        lab = payload.get("lab")
        business_unit = payload.get("business_unit")

        # Check if the essential fields exist
        if not all([first_name, last_name, email, role, lab, business_unit]):
            raise HTTPException(status_code=401, detail="Missing required information in the token")

        # Check if the token has expired
        if "exp" in payload and payload["exp"] < time.time():
            raise HTTPException(status_code=401, detail="Token has expired")

        # Return the extracted information
        return {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "role": role,
            "lab": lab,
            "business_unit": business_unit
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    