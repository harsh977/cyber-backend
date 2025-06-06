import sys
import os

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)

from pymongo import MongoClient
from fastapi.testclient import TestClient
from routers.auth import app  # Assuming this is where your FastAPI app is defined
from dotenv import load_dotenv

load_dotenv()
MONGO_URL = os.getenv("MONGO_URL")
USER_DB = os.getenv("USER_DB")
USER_COLLECTION = os.getenv("USER_COLLECTION")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_login.py <email> <password>")
        sys.exit(1)

    try:
        # Create a test client (does not run the server)
        client = TestClient(app)

        email = sys.argv[1]  # Get email from CLI
        password = sys.argv[2]  # Get password from CLI

        # Call FastAPI POST endpoint for login
        print("Attempting to log in...")

        response = client.post("/auth/login", json={"email": email, "password": password})

        # Check the response status and print it
        if response.status_code == 200:
            print(f"Login successful for email '{email}':", response.json())
        else:
            print(f"Error: {response.json()}")

        # Verify if the user exists in MongoDB (optional, but useful for testing)
        mongo_client = MongoClient(MONGO_URL)
        db = mongo_client[USER_DB]
        collection = db[USER_COLLECTION]

        # Verify if the user is in the database (just to double-check)
        user = collection.find_one({"email": email})
        if user:
            print(f"User {email} exists in the database.")
            print(f"User Details: {user}")
            
            # Ensure that all the necessary fields are present in the database for the user
            required_fields = ["first_name", "last_name", "role", "lab", "business_unit"]
            missing_fields = [field for field in required_fields if field not in user]

            if missing_fields:
                print(f"Error: Missing fields for user {email}: {', '.join(missing_fields)}")
            else:
                print(f"All required fields are present for user {email}.")
        else:
            print(f"User {email} does not exist in the database.")

    except Exception as e:
        print(e)