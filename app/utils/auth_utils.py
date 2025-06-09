from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
from motor.motor_asyncio import AsyncIOMotorCollection

SECRET_KEY = "oieurgbe64rth"  # Use a more secure key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Default expiration time

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Password hashing
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Password verification
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Token creation with dynamic expiration
def create_access_token(data: dict, expires_delta: timedelta = None, remember_me: bool = False):
    to_encode = data.copy()
    
    # Set expiration time based on "remember me"
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # Default expiration is 30 minutes
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        # If "Remember Me" is checked, set expiration to 30 days
        if remember_me:
            expire = datetime.utcnow() + timedelta(days=30)  # 30 days for "Remember Me"
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Initialize the MongoDB collection
async def initialize_collection(collection: AsyncIOMotorCollection):
    """
    Initialize the MongoDB collection with any required indexes or settings.
    """
    # Example: Create a unique index on the "email" field
    await collection.create_index("email", unique=True)