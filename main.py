from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
import jwt
import datetime
from dotenv import load_dotenv
import os
import requests


load_dotenv()

# Environment Variables
SECRET_KEY = os.getenv("SECRET_KEY", "mysecret")
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Mj:ngY5YaP0VjT4BCSt@rfule.gh93u.mongodb.net/?retryWrites=true&w=majority&appName=RFule")

app = FastAPI()

# MongoDB Connection
client = MongoClient(MONGO_URI)
db = client["login_system"]
users_collection = db["users"]
fuel_collection = db["fuel_levels"]
fule_detection_collection = db["fule_detection"]
alert_logs_collection = db["alert_logs"]  # Separate collection for alerts


# Indexing MongoDB for faster queries
users_collection.create_index("phone", unique=True)

# Pydantic Models
class UserRegister(BaseModel):
    name: str
    dob: str
    phone: str
    email: str
    address: str
    vehicle_no: str
    password: str

class UserLogin(BaseModel):
    phone: str
    password: str

class FuelLevelUpdate(BaseModel):
    fuel_level: int

class fuleDetectionUpdate(BaseModel):
    status: str  # Accepts "HIGH" or "LOW"
    address: str  # Address where fule contamination is detected

# Hashing Password
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# JWT Token Generation
def create_jwt_token(phone: str):
    payload = {
        "sub": phone,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Dependency: Authenticate User with JWT
def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user = users_collection.find_one({"phone": payload["sub"]}, {"_id": 0, "password": 0})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Register User
@app.post("/register")
def register_user(user: UserRegister):
    hashed_pw = hash_password(user.password)
    
    if users_collection.find_one({"phone": user.phone}):
        raise HTTPException(status_code=400, detail="Phone number already registered")
    
    users_collection.insert_one({
        "name": user.name,
        "dob": user.dob,
        "phone": user.phone,
        "email": user.email,
        "address": user.address,
        "vehicle_no": user.vehicle_no,
        "password": hashed_pw
    })
    
    return {"message": "User registered successfully"}

# Login User
@app.post("/login")
def login_user(user: UserLogin):
    user_record = users_collection.find_one({"phone": user.phone})
    if user_record and verify_password(user.password, user_record["password"]):
        token = create_jwt_token(user.phone)
        return {"message": "Login successful", "token": token}
    
    raise HTTPException(status_code=401, detail="Invalid phone number or password")

# Protected Route
@app.get("/verify")
def protected_route(user=Depends(get_current_user)):
    return {"message": "Protected content", "user": user}

@app.post("/update-fuel")
def update_fuel_level(fuel_data: FuelLevelUpdate):
    # Ensuring only one document exists for fuel data
    fuel_collection.update_one(
        {},  # Empty filter updates the first available document
        {"$set": {"fuel_level": fuel_data.fuel_level, "last_updated": datetime.datetime.utcnow()}},
        upsert=True  # Creates a document if it doesn't exist
    )
    return {
        "message": "Fuel level updated successfully",
        "fuel_level": fuel_data.fuel_level
    }

# Get Fuel Level
@app.get("/fuel-level")
def get_fuel_level():
    # Get the first document (since it's a single-user application)
    fuel_record = fuel_collection.find_one({}, {"_id": 0})  # Correct query

    if not fuel_record:
        raise HTTPException(status_code=404, detail="Fuel level data not found")

    response = {
        "fuel_level": fuel_record.get("fuel_level", "Unknown"),
        "last_updated": fuel_record.get("last_updated", "No data available")
    }

    # Add alert if fuel level is low
    if isinstance(fuel_record.get("fuel_level"), int) and fuel_record["fuel_level"] <= 30:
        response["alert"] = "Warning: Fuel level is below 30%! Please refill soon."

    return response

# Detect Fuel Theft
@app.get("/detect-theft")
def detect_fuel_theft():
    # Fetch the latest fuel record (since it's a single-user app)
    fuel_record = fuel_collection.find_one({}, {"_id": 0})  # Correct query

    if not fuel_record:
        raise HTTPException(status_code=404, detail="Fuel level data not found")

    last_fuel_level = fuel_record.get("fuel_level")
    last_updated = fuel_record.get("last_updated")

    # Ensure both fuel level and timestamp exist
    if last_fuel_level is not None and last_updated:
        time_difference = datetime.datetime.utcnow() - last_updated

        # If the fuel level dropped by more than 10 units within 2 minutes, trigger theft alert
        if time_difference.total_seconds() < 120 and last_fuel_level - fuel_record["fuel_level"] > 10:
            return {"alert": " Fuel theft detected! Immediate drop in fuel level."}

    return {"message": "No theft detected"}

# 🚰 **1️⃣ Detect fule Contamination & Store Alert**
@app.post("/detect-fule")
def detect_fule_contamination(fule_data: fuleDetectionUpdate):
    timestamp = datetime.datetime.utcnow()
    formatted_timestamp = timestamp.isoformat()

    # Debugging: Print the received data
    print(f"📢 Received data: status={fule_data.status}, address={fule_data.address}")

    # Prepare the document to be inserted
    fule_data_entry = {
        "status": fule_data.status,
        "address": fule_data.address,
        "last_updated": timestamp
    }

    # Insert instead of updating (to allow multiple records)
    try:
        result = fule_detection_collection.insert_one(fule_data_entry)
        print(f"Successfully inserted! Inserted ID: {result.inserted_id}")
    except Exception as e:
        print(f" MongoDB Insert Error: {e}")
        raise HTTPException(status_code=500, detail="Database insert failed")

    # Alert message
    alert_message = " fule contamination detected! Immediate action required."

    # Insert alert in `alert_logs_collection`
    alert_entry = {
        "alert": alert_message,
        "address": fule_data.address,
        "last_updated": timestamp
    }

    try:
        alert_logs_collection.insert_one(alert_entry)
        print(" Alert saved successfully!")
    except Exception as e:
        print(f"❌ MongoDB Insert Error in alert_logs: {e}")
        raise HTTPException(status_code=500, detail="Alert logging failed")

    return {
        "message": "Update Sucessfully",
    }


# 📢 **2️⃣ Fetch the Latest Alert Message**
@app.get("/get-latest-alert")
def get_latest_alert():
    latest_alert = alert_logs_collection.find_one({}, sort=[("last_updated", -1)])

    if not latest_alert:
        raise HTTPException(status_code=404, detail="No alerts found.")

    return {
        "alert": latest_alert.get("alert", " No recent alerts."),
        "address": latest_alert.get("address", "Unknown location."),
        "last_updated": latest_alert.get("last_updated", "No timestamp available.")
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
