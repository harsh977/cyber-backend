import sys
import os


# Add the parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# Now import utils
from utils.auth_utils import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, hash_password

from fastapi import APIRouter, HTTPException, Depends, Request, Header
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorCollection
from fastapi.responses import JSONResponse
from datetime import timedelta
from typing import List, Optional
from enum import Enum
from datetime import datetime
import pytz
import jwt
import random
import time
from dotenv import load_dotenv


load_dotenv()
USER_COLLECTION = os.getenv("USER_COLLECTION")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

from connection.connection import mongo_connection

router = APIRouter()


# Pydantic Models
class User(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = None  # Role Selection (Admin, Manager, Researcher, Viewer)
    lab: Optional[str] = None  # Lab Selection
    business_unit: Optional[str] = None  # Business Unit Selection
    dashboard_view: Optional[str] = None # Preferred Dashboard View
    notification_preferences: Optional[List[str]] = None  # Notification Preferences (email, SMS, app)
    tfa_enabled: Optional[bool] = True
    #terms_accepted: bool  # Terms & Conditions Agreement
    # security_question: Optional[str] = None
    # security_answer: Optional[str] = None

    class Config:
        from_attributes = True


class RoleEnum(str, Enum):
    Admin = "Admin"
    Manager = "Manager"
    Researcher = "Researcher"
    Viewer = "Viewer"


class BusinessUnitEnum(str, Enum):
    Server = "Server"
    Hybrid_Cloud = "Hybrid Cloud"
    Intelligent_Edge = "Intelligent Edge"
    Financial_Services = "Financial Services"
    Corporate_Investments = "Corporate Investments & Other"
    HPC_AI = "Compute, High Performance Computing & AI"
    Software = "Software"
    Storage = "Storage"


class LabEnum(str, Enum):
    Lab1 = "Lab1"
    Lab2 = "Lab2"
    Lab3 = "Lab3"

class NotificationPreferenceEnum(str, Enum):
    Email = "Email"
    SMS = "SMS"
    App = "App"


# class DashboardViewEnum(str):
#     Summary = "Summary"
#     Detailed = "Detailed"
#     Graphical = "Graphical"

class Token(BaseModel):
    access_token: str
    token_type: str
    email: str
    is_admin: bool

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp: int



############################### DASHBOARD START ###################################
class AccessAttempt(BaseModel):
    user_email: str
    ip_address: str
    timestamp: datetime
    status: str  # "success" or "failed"
    user_agent: Optional[str] = None

class AccessStats(BaseModel):
    active_users: int
    access_attempts_24h: int
    mfa_compliance: float
    failed_logins: int
############################### DASHBOARD END ###################################









# Signup endpoint
@router.post("/auth/signup")
async def signup(user: User):
    db = await mongo_connection.connect()
    collection = db[USER_COLLECTION]

    if collection is None:
        raise HTTPException(status_code=500, detail="Database not initialized.")
    
    # Check if the email already exists in the collection
    existing_user = await collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists.")
    
    # Validate role if necessary (optional)
    if user.role.upper() not in (role.upper() for role in RoleEnum.__members__):
        raise HTTPException(status_code=400, detail="Invalid role")
    
    if user.business_unit.upper() not in (business_unit.upper() for business_unit in BusinessUnitEnum.__members__):
        raise HTTPException(status_code=400, detail="Invalid Business Unit")
    
    if user.lab.upper() not in (lab.upper() for lab in LabEnum.__members__):
        raise HTTPException(status_code=400, detail="Invalid Lab Number")

    # Hash the password before storing it
    user.password = hash_password(user.password)
    
    # Insert the new user document into the collection
    await collection.insert_one(user.dict())
    return {"message": "User registered successfully"}



############################### DASHBOARD START ###################################
# Login endpoint with Remember Me option
@router.post("/auth/login", response_model=Token)
async def login(user: User, request: Request, remember_me: Optional[bool] = False):
############################### DASHBOARD END ###################################


    db = await mongo_connection.connect()
    collection = db[USER_COLLECTION]

    if collection is None:
        raise HTTPException(status_code=500, detail="Database not initialized.")
    
    query = query = {"email": user.email}
    db_user = await collection.find_one(query)


############################### DASHBOARD START ###################################
    if not db_user or not verify_password(user.password, db_user['password']):
        # Log failed access attempt
        access_log = {
            "user_email": user.email,
            "ip_address": request.client.host if hasattr(request, 'client') else "unknown",
            "timestamp": datetime.utcnow(),
            "status": "failed"
        }
        await db["access_logs"].insert_one(access_log)

        raise HTTPException(status_code=401, detail="Invalid email or password")
############################### DASHBOARD END ###################################

    # Check if TFA is enabled
    

    # If no TFA, continue normal login process
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    if remember_me:
        expires_delta = timedelta(days=30)  # Extend token expiration if Remember Me is checked
    
    access_token = create_access_token(
        data={
            "sub": db_user['email'],  # Subject (user identifier)
            "first_name": db_user['first_name'],
            "last_name": db_user['last_name'],
            "email": db_user['email'],
            "role": db_user['role'],
            "lab": db_user['lab'],
            "business_unit": db_user['business_unit'],
        },
        expires_delta=expires_delta
    )
    
############################### DASHBOARD START ###################################

    # Add this right after the successful login, before returning the token
    # Log successful access attempt
    access_log = {
        "user_email": db_user['email'],
        "ip_address": request.client.host if hasattr(request, 'client') else "unknown",
        "timestamp": datetime.utcnow(),
        "status": "success"
    }
    await db["access_logs"].insert_one(access_log)
############################### DASHBOARD END ###################################


    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "email": db_user['email'], 
        "is_admin": db_user['role'].lower() == "admin"
    }



@router.post("/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    db = await mongo_connection.connect()
    collection = db[USER_COLLECTION]

    user = await collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")

    # 1. Create reset token (15 min expiry)
    reset_token = jwt.encode(
    {
        "sub": user["email"],
        "exp": datetime.utcnow() + timedelta(minutes=15)
    },
    SECRET_KEY,
    algorithm = ALGORITHM
    )   

    # 2. Build reset link
    reset_link = f"https://yourfrontend.com/reset-password?token={reset_token}"

    # 3. Send email (replace with your actual email sending logic)
    send_reset_email(user["email"], reset_link)

    return {"message": "Password reset link sent to your email."}





############################### DASHBOARD START ###################################
@router.get("/auth/access-stats")
async def get_access_stats(user_email: str = Header(..., alias="user_email")):  # Get email from header
    db = await mongo_connection.connect()
    
    # Check if user exists AND is an admin
    user = await db[USER_COLLECTION].find_one({"email": user_email})
    if not user or user["role"].lower() != "admin":  # Role check
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get current time and 24 hours ago
    now = datetime.utcnow()
    twenty_four_hours_ago = now - timedelta(hours=24)
    
    # Active users (successful logins in last 24 hours)
    active_users = await db["access_logs"].distinct("user_email", {
        "status": "success",
        "timestamp": {"$gte": twenty_four_hours_ago}
    })
    
    # Total access attempts in last 24 hours
    access_attempts_24h = await db["access_logs"].count_documents({
        "timestamp": {"$gte": twenty_four_hours_ago}
    })
    
    # Failed logins in last 24 hours
    failed_logins = await db["access_logs"].count_documents({
        "status": "failed",
        "timestamp": {"$gte": twenty_four_hours_ago}
    })
    
    # MFA compliance (percentage of users with TFA enabled)
    total_users = await db[USER_COLLECTION].count_documents({})
    mfa_enabled_users = await db[USER_COLLECTION].count_documents({"tfa_enabled": True})
    mfa_compliance = (mfa_enabled_users / total_users * 100) if total_users > 0 else 0
    
    return {
        "active_users": len(active_users),
        "access_attempts_24h": access_attempts_24h,
        "mfa_compliance": round(mfa_compliance, 1),
        "failed_logins": failed_logins
    }

@router.get("/auth/recent-access-events")
async def get_recent_access_events(
    limit: int = 10,
    user_email: str = Header(..., alias="user_email")
):
    # Verify admin role
    db = await mongo_connection.connect()
    
    # Check if user exists AND is an admin
    user = await db[USER_COLLECTION].find_one({"email": user_email})
    if not user or user["role"].lower() != "admin":  # Role check
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get recent access attempts
    recent_events = await db["access_logs"].find().sort("timestamp", -1).limit(limit).to_list(length=limit)
    
    # Format the response
    formatted_events = []
    for event in recent_events:
        formatted_events.append({
            "user": event.get("user_email", "unknown"),
            "ip_address": event.get("ip_address", "unknown"),
            "timestamp": event["timestamp"],
            "status": event["status"]
        })
    
    return {"events": formatted_events}

@router.get("/auth/active-users")
async def get_active_users(
    user_email: str = Header(..., alias="user_email")
):
    # Verify admin role
    db = await mongo_connection.connect()

    # Check if user exists AND is an admin
    user = await db[USER_COLLECTION].find_one({"email": user_email})
    if not user or user["role"].lower() != "admin":  # Role check
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get users who logged in successfully in the last 24 hours
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    
    active_users = await db["access_logs"].aggregate([
        {"$match": {
            "status": "success",
            "timestamp": {"$gte": twenty_four_hours_ago}
        }},
        {"$group": {
            "_id": "$user_email",
            "last_login": {"$max": "$timestamp"},
            "ip_address": {"$last": "$ip_address"}
        }},
        {"$sort": {"last_login": -1}}
    ]).to_list(length=None)
    
    return {"active_users": active_users, "count": len(active_users)}



@router.get("/auth/access-control")
async def check_admin_status(user_email: str = Header(..., alias="user_email")):
    db = await mongo_connection.connect()
    user = await db[USER_COLLECTION].find_one({"email": user_email})
    
    is_admin = bool(user and user["role"].lower() == "admin")
    
    return {
        "is_admin": is_admin,  # returns True/False
        "message": "Admin access granted" if is_admin else "Access restricted to admins"
    }
############################### DASHBOARD END ###################################















################# HELPER FUNCTIONS #################
import smtplib
from email.message import EmailMessage

def send_reset_email(to_email: str, reset_link: str):
    india_tz = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(india_tz).strftime('%d/%m/%Y %H:%M:%S %Z')

    email_address = os.getenv("EMAIL_ADDRESS")
    email_password = os.getenv("EMAIL_PASSWORD")
    email_host = os.getenv("EMAIL_HOST")
    email_port = int(os.getenv("EMAIL_PORT"))

    msg = EmailMessage()
    msg["Subject"] = "Reset Your Password"
    msg["From"] = email_address
    msg["To"] = to_email
    msg.set_content(f"Your password reset link is given below. It is valid for the next 15 minutes starting from ({current_time}):\n\n{reset_link}")

    with smtplib.SMTP_SSL(email_host, email_port) as smtp:
        smtp.login(email_address, email_password)
        smtp.send_message(msg)



def send_otp_email(to_email: str, otp: int):
    india_tz = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(india_tz).strftime('%d/%m/%Y %H:%M:%S %Z')

    email_address = os.getenv("EMAIL_ADDRESS")
    email_password = os.getenv("EMAIL_PASSWORD")
    email_host = os.getenv("EMAIL_HOST")
    email_port = int(os.getenv("EMAIL_PORT"))

    msg = EmailMessage()
    msg["Subject"] = "Your OTP for Two-Factor Authentication"
    msg["From"] = email_address
    msg["To"] = to_email
    msg.set_content(f"Your OTP is <b>[{otp}]</b>. It is valid for the next 15 minutes starting from ({current_time}). Please enter it on the login page to complete your authentication.", subtype='html')

    with smtplib.SMTP_SSL(email_host, email_port) as smtp:
        smtp.login(email_address, email_password)
        smtp.send_message(msg)

