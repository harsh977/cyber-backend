import sys
import os
import asyncio
from fastapi.testclient import TestClient

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
sys.path.append(project_root)

from routers.auth import app
from dotenv import load_dotenv

load_dotenv()
MONGO_URL = os.getenv("MONGO_URL")
USER_DB = os.getenv("USER_DB")
USER_COLLECTION = os.getenv("USER_COLLECTION")

async def run_test(email: str, password: str):
    with TestClient(app) as client:
        try:
            # Login request
            login_response = client.post(
                "/auth/login",
                json={"email": email, "password": password}
            )
            
            print(f"Status: {login_response.status_code}")
            print(f"Response: {login_response.json()}")

            if login_response.status_code == 200:
                print("\nLogin successful!")
                print(f"Token: {login_response.json()['access_token']}")
                return
                
            elif login_response.status_code == 202:
                print("\nTFA required")
                otp = input("Enter OTP from email: ")
                
                # OTP verification with proper error handling
                otp_response = client.post(
                    "/auth/verify-otp",
                    json={"email": email, "otp": int(otp)}
                )
                
                if otp_response.status_code == 200:
                    print("\nOTP verified!")
                    print(f"Token: {otp_response.json()['access_token']}")
                else:
                    # Handle 400 and other errors gracefully
                    print(f"\nOTP failed: {otp_response.json().get('detail', 'Unknown error')}")
                return

            print("\nLogin failed:", login_response.json())
            
        except Exception as e:
            # This will catch any unexpected errors
            print(f"\nUnexpected error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_loginWithTFA.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]
    
    asyncio.run(run_test(email, password))