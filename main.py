from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
import jwt
from datetime import datetime  # Import the datetime class
from dotenv import load_dotenv
import os
import requests


load_dotenv()

# Environment Variables
SECRET_KEY = os.getenv("SECRET_KEY", "mysecret")
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Mj:ngY5YaP0VjT4BCSt@rfule.gh93u.mongodb.net/?retryWrites=true&w=majority&appName=RFule")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to ["https://yourfrontend.com"] in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Connection
client = MongoClient(MONGO_URI)
db = client["login_system"]
users_collection = db["users"]
fuel_collection = db["fuel_levels"]
fule_detection_collection = db["fule_detection"]
alert_logs_collection = db["alert_logs"]  # Separate collection for alerts
device_status_collection = db["device_status"]


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

class FuleDetectionUpdate(BaseModel):
    status: str  # Accepts "HIGH" or "LOW"
    address: str  # Location where fuel contamination is detected
    previous_fuel_level: float  # Fuel level before contamination
    current_fuel_level: float   # Fuel level after contamination

    
class DeviceStatusUpdate(BaseModel):
    status: str  # Accepts "active" or "deactive"

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
    current_time = datetime.utcnow()

    # Fetch the most recent fuel level
    last_fuel_record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if last_fuel_record:
        last_fuel_level = last_fuel_record.get("fuel_level", None)
    else:
        last_fuel_level = None  # No previous record found

    # Update the fuel level and keep the previous level stored
    fuel_collection.insert_one({
        "previous_fuel_level": last_fuel_level,  # Store old fuel level
        "fuel_level": fuel_data.fuel_level,  # Store new fuel level
        "last_updated": current_time
    })

    return {
        "message": "Fuel level updated successfully",
        "previous_fuel_level": last_fuel_level,
        "current_fuel_level": fuel_data.fuel_level
    }

# Get Fuel Level
@app.get("/fuel-level")
def get_fuel_level():
    # Fetch the most recent fuel level entry
    fuel_record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if not fuel_record:
        raise HTTPException(status_code=404, detail="Fuel level data not found")

    # Debugging: Print fetched data
    print(f"Fetched Fuel Record: {fuel_record}")

    response = {
        "fuel_level": fuel_record.get("fuel_level", "Unknown"),
        "last_updated": fuel_record.get("last_updated", "No data available")
    }

    # Add alert if fuel level is low
    if isinstance(fuel_record.get("fuel_level"), int) and fuel_record["fuel_level"] <= 30:
        response["alert"] = " Warning: Fuel level is below 30%! Please refill soon."

    return response

# Detect Fuel Theft
@app.get("/detect-fule")
def detect_fuel_contamination():
    timestamp = datetime.utcnow()  # Correct way to get current UTC time

    # Fetch the most recent fuel level entry from MongoDB
    last_fuel_record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if not last_fuel_record:
        raise HTTPException(status_code=404, detail="Fuel level data not found")

    previous_fuel_level = last_fuel_record.get("previous_fuel_level", 0)
    current_fuel_level = last_fuel_record.get("fuel_level", 0)

    # Calculate contamination level (percentage of fuel loss)
    if previous_fuel_level > 0:
        contamination_level = ((previous_fuel_level - current_fuel_level) / previous_fuel_level) * 100
    else:
        contamination_level = 0  # Avoid division by zero

    # Prepare response
    response = {
        "message": "Fuel contamination detected",
        "previous_fuel_level": previous_fuel_level,
        "current_fuel_level": current_fuel_level,
        "contamination_level": round(contamination_level, 2),
        "last_updated": last_fuel_record.get("last_updated")
    }

    # Store contamination data into `fule_detection_collection`
    fule_detection_collection.insert_one({
        "status": "HIGH" if contamination_level > 10 else "LOW",
        "address": "Unknown",  # No address in GET request
        "contamination_level": contamination_level,
        "previous_fuel_level": previous_fuel_level,
        "current_fuel_level": current_fuel_level,
        "last_updated": timestamp
    })

    # Store alert in `alert_logs_collection`
    alert_message = f" Fuel contamination detected! Contamination Level: {contamination_level:.2f}%."
    alert_logs_collection.insert_one({
        "message": alert_message,
        "timestamp": timestamp
    })

    return response
@app.get("/detect-theft")
def detect_fuel_theft():
    fuel_record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if not fuel_record:
        return {"message": "No theft detected"}

    last_fuel_level = fuel_record.get("previous_fuel_level", 0)
    current_fuel_level = fuel_record.get("fuel_level", 0)
    last_updated = fuel_record.get("last_updated")

    if last_fuel_level is None or last_updated is None:
        return {"message": "No theft detected"}

    if isinstance(last_updated, str):
        last_updated = datetime.strptime(last_updated, "%Y-%m-%d %H:%M:%S")

    time_difference = datetime.utcnow() - last_updated

    print(f"Previous Fuel Level: {last_fuel_level}, Current Fuel Level: {current_fuel_level}, Time Difference: {time_difference.total_seconds()}s")

    if time_difference.total_seconds() < 120 and last_fuel_level > current_fuel_level and (last_fuel_level - current_fuel_level) > 10:
        return {
            "message": "Theft detected",
            "alert": " Fuel theft detected! Immediate drop in fuel level."
        }

    return {"message": "No theft detected"}
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
