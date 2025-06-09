from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
from typing import List, Optional
from connection.connection import get_parsed_collection
from pydantic import BaseModel
import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from utils.auth_utils import SECRET_KEY, ALGORITHM

router = APIRouter()
security = HTTPBearer()

class UserResponse(BaseModel):
    email: str
    first_name: str
    last_name: str
    role: str
    lab: str
    business_unit: str
    dashboard_view: str
    notification_preferences: List[str]
    tfa_enabled: bool

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        print("Verifying token...")
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        exp = payload.get("exp")
        if exp is None:
            print("Token has no expiration")
            raise HTTPException(status_code=401, detail="Token has no expiration")
        if datetime.utcnow().timestamp() > exp:
            print("Token has expired")
            raise HTTPException(status_code=401, detail="Token has expired")

        print("Token verified successfully.")
        return payload
    except jwt.ExpiredSignatureError:
        print("Token expired (JWT error)")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        print("Invalid token (JWT error)")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Authentication error: {str(e)}")

@router.get("/users", response_model=List[UserResponse])
async def get_users_by_lab(
    business_unit: Optional[str] = None,
    token_data: dict = Depends(verify_token)
):
    try:
        print("Inside /users route handler")

        user_role = token_data.get("role")
        user_lab = token_data.get("lab")
        user_email = token_data.get("sub")

        print(f"Token data — Role: {user_role}, Lab: {user_lab}, Email: {user_email}")

        if user_role.lower() != "admin":
            print("User is not admin")
            raise HTTPException(
                status_code=403,
                detail="Permission denied. Only administrators can access user details."
            )

        query = {"lab": user_lab}
        if business_unit:
            query["business_unit"] = business_unit

        print(f"MongoDB query: {query}")

        collection = await get_parsed_collection()
        print("Got parsed collection")

        cursor = collection.find(query)
        print("Executed MongoDB find")

        users = []
        async for user in cursor:
            print(f"Found user: {user}")
            user.pop("_id", None)
            user.pop("password", None)
            users.append(user)

        print(f"Total users found: {len(users)}")
        return users or []

    except HTTPException as he:
        print(f"HTTP Exception: {he.detail}")
        raise he
    except Exception as e:
        print(f"General exception: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve users: {str(e)}"
        )
