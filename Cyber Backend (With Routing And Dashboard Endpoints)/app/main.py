from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from routers.auth import router as auth_router
from routers.graph_routes import routers as graph_routers
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

from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")
USER_DB = os.getenv("USER_DB")
USER_COLLECTION = os.getenv("USER_COLLECTION")

client = AsyncIOMotorClient(MONGO_URL)
db = client[USER_DB]  # This is the actual database object
collection = db[USER_COLLECTION]  # This is the actual collection objects



@app.on_event("startup")
async def startup_db():
    await initialize_collection(collection)

app.include_router(auth_router)

for r in graph_routers:
    app.include_router(r)




@app.get("/")
async def root():
    return {"message": "Connected to MongoDB Atlas!"}
