from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import requests
import pytz  # ← Add this line
import smtplib
from email.mime.text import MIMEText


load_dotenv()

# Environment Variables
SECRET_KEY = os.getenv("SECRET_KEY", "mysecret")
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Mj:ngY5YaP0VjT4BCSt@rfule.gh93u.mongodb.net/?retryWrites=true&w=majority&appName=RFule")
# Email Credentials
SENDER_EMAIL = "codeinlastbench@gmail.com"
RECIPIENT_EMAIL = "manojmahato08779@gmail.com"
APP_PASSWORD = "hloo qrlt qyvj hmak"  # Your Gmail App Password

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

    
class DeviceStatusUpdate(BaseModel):
    status: str  # Accepts "active" or "deactive"

# Hashing Password
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def send_email_alert(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
        print("✅ Email alert sent successfully!")
    except Exception as e:
        print("❌ Failed to send email:", e)


def get_ist_time(dt_utc):
    if dt_utc:
        utc_time = dt_utc.replace(tzinfo=pytz.UTC)
        ist_time = utc_time.astimezone(pytz.timezone("Asia/Kolkata"))
        return ist_time.strftime("%Y-%m-%d %H:%M:%S")
    return "No timestamp available."
        
# JWT Token Generation
def create_jwt_token(phone: str):
    payload = {
        "sub": phone,
        "exp": datetime.utcnow() + timedelta(hours=24)  # Fix here
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
    "message": "Fuel contamination data recorded successfully",
    "contamination_level": contamination,
    "previous_fuel_level": prev,
    "current_fuel_level": curr
}


@app.get("/fuel-level")
def get_fuel_level():
    fuel_record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if not fuel_record:
        raise HTTPException(status_code=404, detail="Fuel level data not found")

    fuel_level = fuel_record.get("fuel_level", "Unknown")
    last_updated = fuel_record.get("last_updated")
    time_ist = get_ist_time(last_updated)

    response = {
        "fuel_level": fuel_level,
        "last_updated": time_ist
    }

    if isinstance(fuel_level, int) and fuel_level <= 30:
        alert_msg = f"""
        ⚠️ Alert: Fuel level is critically low!

        Fuel Level: {fuel_level}%
        Time: {time_ist}

        Please refill the tank as soon as possible.
        """
        response["alert"] = " Warning: Fuel level is below 30%! Please refill soon."
        send_email_alert("⚠️ Fuel Level Alert", alert_msg)

        alert_logs_collection.insert_one({
            "alert": response["alert"],
            "address": "Unknown",
            "last_updated": last_updated
        })

    return response


@app.post("/detect-fuel")
def detect_fuel_contamination(data: FuleDetectionUpdate):
    timestamp = datetime.utcnow()
    record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if not record:
        raise HTTPException(status_code=404, detail="Fuel level data not found")

    prev = record.get("previous_fuel_level", 0)
    curr = record.get("fuel_level", 0)

    contamination = ((prev - curr) / prev) * 100 if prev > 0 else 0
    contamination = round(contamination, 2)

    fule_detection_collection.insert_one({
        "status": data.status,
        "address": data.address,
        "contamination_level": contamination,
        "previous_fuel_level": prev,
        "current_fuel_level": curr,
        "last_updated": timestamp
    })

    # Optional: Email only on HIGH contamination
    if data.status.upper() == "HIGH":
        alert_msg = f"""
         High fuel contamination detected!

        Address: {data.address}
        Contamination Level: {contamination}%
        Previous Fuel Level: {prev}
        Current Fuel Level: {curr}
        Time: {get_ist_time(timestamp)}

        Immediate inspection is recommended.
        """
        send_email_alert(" Fuel Contamination Alert", alert_msg)

    alert_logs_collection.insert_one({
        "alert": f"Fuel contamination level: {contamination}%",
        "status": data.status,
        "address": data.address,
        "last_updated": timestamp
    })

    return {
        "message": "Fuel contamination data recorded successfully",
        "contamination_level": contamination,
        "status": data.status
    }

@app.get("/contamination-report")
def get_latest_contamination():
    record = fule_detection_collection.find_one({}, sort=[("last_updated", -1)])

    if not record:
        raise HTTPException(status_code=404, detail="No contamination data found")

    return {
        "contamination_level": record.get("contamination_level", 0),
        "previous_fuel_level": record.get("previous_fuel_level", 0),
        "current_fuel_level": record.get("current_fuel_level", 0),
        "timestamp": get_ist_time(record.get("last_updated"))
    }



@app.get("/detect-theft")
def detect_fuel_theft():
    record = fuel_collection.find_one({}, sort=[("last_updated", -1)])

    if not record:
        return {"message": "No theft detected"}

    prev = record.get("previous_fuel_level", 0)
    curr = record.get("fuel_level", 0)
    last_updated = record.get("last_updated")

    if not prev or not last_updated:
        return {"message": "No theft detected"}

    if isinstance(last_updated, str):
        last_updated = datetime.strptime(last_updated, "%Y-%m-%d %H:%M:%S")

    time_diff = (datetime.utcnow() - last_updated).total_seconds()

    if time_diff < 120 and prev > curr and (prev - curr) > 10:
        alert = " Fuel theft detected! Sudden drop in fuel level."
        alert_logs_collection.insert_one({
            "alert": alert,
            "address": "Unknown",
            "last_updated": datetime.utcnow()
        })

        send_email_alert("🚨 Fuel Theft Detected", f"""
        🚨 Alert: Fuel theft suspected!

        Previous Level: {prev}%
        Current Level: {curr}%
        Time: {get_ist_time(last_updated)}

        Immediate action is advised.
        """)

        return {
            "message": "Theft detected",
            "alert": alert
        }

    return {"message": "No theft detected"}


@app.get("/get-latest-alert")
def get_latest_alert():
    alert = alert_logs_collection.find_one({}, sort=[("last_updated", -1)])

    if not alert:
        raise HTTPException(status_code=404, detail="No alerts found.")

    return {
        "alert": alert.get("alert", "No recent alerts."),
        "address": alert.get("address", "Unknown location."),
        "last_updated": get_ist_time(alert.get("last_updated"))
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
