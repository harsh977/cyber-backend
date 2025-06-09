import sys
import os
import jwt

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)

from fastapi.testclient import TestClient
from routers.auth import app
from pymongo import MongoClient
from dotenv import load_dotenv
from utils.auth_utils import verify_password

load_dotenv()
MONGO_URL = os.getenv("MONGO_URL")
USER_DB = os.getenv("USER_DB")
USER_COLLECTION = os.getenv("USER_COLLECTION")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_resetpassword.py <reset_token> <new_password>")
        sys.exit(1)

    try:
        client = TestClient(app)

        token = sys.argv[1]
        new_password = sys.argv[2]

        print("Attempting to reset password...")

        response = client.post("/auth/reset-password", json={
            "token": token,
            "new_password": new_password
        })

        if response.status_code == 200:
            print("Password reset successful:", response.json())
        else:
            print("Password reset failed:", response.status_code, response.json())

        # Decode token to get email
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        # Connect to DB and fetch updated user
        mongo_client = MongoClient(MONGO_URL)
        db = mongo_client[USER_DB]
        collection = db[USER_COLLECTION]
        user_after = collection.find_one({"email": email})

        if user_after and verify_password(new_password, user_after["password"]):
            print("\nPassword updated and verified successfully.")
        else:
            print("\nPassword update failed. Hash mismatch or user not found.")

    except Exception as e:
        print("Error:", e)
