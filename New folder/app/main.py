from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from routers.auth import router as auth_router
from routers.upload import router as upload_router
from routers.upload2 import router as upload2_router
from routers.upload3 import router as upload3_router
from utils.auth_utils import initialize_collection
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB configuration
MONGO_URL = "mongodb+srv://harshdaftari2:harsh03032004@cluster0.exftgxj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = AsyncIOMotorClient(MONGO_URL)
database = client.user_input_file_db
collection = database.users

@app.on_event("startup")
async def startup_db():
    await initialize_collection(collection)

app.include_router(auth_router)
app.include_router(upload_router)
app.include_router(upload2_router)
app.include_router(upload3_router)

@app.get("/")
async def root():
    return {"message": "Connected to MongoDB Atlas!"}
