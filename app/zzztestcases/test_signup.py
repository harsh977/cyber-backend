# # Dynamically add the root project directory to the PYTHONPATH
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)

from pymongo import MongoClient
from fastapi.testclient import TestClient
from routers.auth import app  # Assuming this is where your FastAPI app is defined

# Add the project root directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)

from dotenv import load_dotenv

load_dotenv()
MONGO_URL = os.getenv("MONGO_URL")
USER_DB = os.getenv("USER_DB")
USER_COLLECTION = os.getenv("USER_COLLECTION")

if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("Usage: python test_signup.py <First Name> <Last Name> <Email> <Password> <Role> <Lab> <Business Unit>")
        sys.exit(1)

    try:
        # Create a test client (does not run the server)
        client = TestClient(app)  

        first_name = sys.argv[1]  # Get first name from CLI
        last_name = sys.argv[2]   # Get last name from CLI
        email = sys.argv[3]       # Get email from CLI
        password = sys.argv[4]    # Get password from CLI
        role = sys.argv[5]        # Get role from CLI
        lab = sys.argv[6]         # Get lab from CLI
        business_unit = sys.argv[7]  # Get business unit from CLI

        # Call FastAPI POST endpoint for signup
        print("Attempting to sign up...")

        response = client.post("/auth/signup", json={
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": password,
            "role": role,
            "lab": lab,
            "business_unit": business_unit
        })

        # Check the response status and print it
        if response.status_code == 200:
            print(f"Signup successful for {first_name} {last_name} ({email}):", response.json())
        else:
            print(f"Error: {response.json()}")

        # Verify if the user exists in MongoDB
        mongo_client = MongoClient(MONGO_URL)
        db = mongo_client[USER_DB]
        collection = db[USER_COLLECTION]

        # Verify if the user was added to the database
        new_user = collection.find_one({"email": email})
        if new_user:
            print(f"User {email} exists in the database.")
        else:
            print(f"User {email} does not exist in the database.")

    except Exception as e:
        print(e)



