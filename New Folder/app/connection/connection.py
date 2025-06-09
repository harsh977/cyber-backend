# Dynamically add the root project directory to the PYTHONPATH
import sys
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)  

# Load environment variables from .env file
load_dotenv()

# Get MongoDB URL and database name from environment variables
MONGO_URL = os.getenv("MONGO_URL")
USER_DB = os.getenv("USER_DB")
USER_COLLECTION = os.getenv("USER_COLLECTION")

class MongoDBConnection:
    def __init__(self):
        self.client = None
        self.db = None

    async def connect(self):
        """Establishes a MongoDB connection only if not already connected."""
        if self.client is None:
            try:
                self.client = AsyncIOMotorClient(MONGO_URL)
                self.db = self.client[USER_DB]
                print("Connection established: DL to DB")
            except Exception as e:
                raise Exception(f"MongoDB Connection Error: {str(e)}")
        return self.db

    async def close(self):
        """Closes the MongoDB connection if it exists."""
        if self.client:
            try:
                self.client.close()
                self.client = None
            except Exception as e:
                raise Exception(f"Error closing MongoDB connection: {str(e)}")

# Create a single instance to reuse
mongo_connection = MongoDBConnection()

# Access the collection only when needed (lazy loading)
async def get_parsed_collection():
    """Returns the parsed file collection (establishes connection if needed)."""
    db = await mongo_connection.connect()  # <-- CALL the method with ()
    return db[USER_COLLECTION]             # <-- THEN access the collection

async def get_uploaded_files_collection():
    """
    Returns the collection for uploaded files.
    """
    db = await mongo_connection.connect()
    return db["uploaded_files"]  # Use a dedicated collection for uploads
