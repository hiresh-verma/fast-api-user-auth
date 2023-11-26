from pymongo import mongo_client
import pymongo
from app.config import settings

client = mongo_client.MongoClient(
    settings.DATABASE_URL, serverSelectionTimeoutMS=5000)

try:
    conn = client.server_info()
    print(f'Connected to MongoDB')
except Exception as exc:
    print("Unable to connect to the MongoDB server.")
    print(exc)

db = client[settings.MONGO_INITDB_DATABASE]

User = db.users
User.create_index([("email", pymongo.ASCENDING)], unique=True)

Otp = db.otp
Otp.create_index([("email", pymongo.ASCENDING)], unique=True)
Otp.create_index([("expires_after", pymongo.ASCENDING)], unique=True, expireAfterSeconds=43200)
