import json
import uuid
import base64
import requests
from datetime import datetime, timedelta,UTC
from nacl.signing import SigningKey
import os
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from dotenv import load_dotenv
from cryptic_utils import *
import datetime

load_dotenv()

# Load environment variables
SIGNING_PRIVATE_KEY_BASE64 = os.getenv("Signing_private_key")
SIGNING_PUBLIC_KEY = os.getenv("Signing_public_key")
ENCRYPTION_PRIVATE_KEY_BASE64 = os.getenv("Encryption_Privatekey")
ENCRYPTION_PUBLIC_KEY = os.getenv("Encryption_Publickey")
SUBSCRIBER_ID = os.getenv("SUBSCRIBER_ID")
UNIQUE_KEY_ID = os.getenv("UNIQUE_KEY_ID")
print(SUBSCRIBER_ID, UNIQUE_KEY_ID, SIGNING_PUBLIC_KEY, ENCRYPTION_PUBLIC_KEY)

# Helper functions
def get_timestamp():
    return datetime.datetime.utcnow().isoformat(timespec='milliseconds') + "Z"

def get_valid_until():
    return (datetime.datetime.utcnow()  + datetime.timedelta(days=365)).isoformat(timespec='milliseconds') + "Z"

def generate_signature(message: str, private_key_base64: str):
    private_key_bytes = base64.b64decode(private_key_base64)
    seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
    signing_key = SigningKey(seed)
    signed = signing_key.sign(message.encode('utf-8'))
    signature = base64.b64encode(signed.signature).decode('utf-8')
    return signature

# def create_authorisation_header(request_body=None, created=None, expires=None):
#     request_body = request_body 
#     if request_body is None:
#         raise ValueError("Request body not found or invalid.")
    
#     if created is None:
#         created = int(datetime.datetime.now().timestamp()) - 1000

#     if expires is None:
#         expires = int((datetime.datetime.now() + datetime.timedelta(minutes=10)).timestamp())

    
    

#     signing_key = create_signing_string(hash_message(request_body), created, expires)
#     print("Signing Key:", signing_key)  # For debugging
#     signature = sign_response(signing_key, private_key=os.getenv("Signing_private_key"))

#     subscriber_id = os.getenv("SUBSCRIBER_ID", "buyer-app.ondc.org")
#     unique_key_id = os.getenv("UNIQUE_KEY_ID", "207")
#     header = (
#         f'Signature keyId="{subscriber_id}|{unique_key_id}|ed25519",'
#         f'algorithm="ed25519",created="{created}",expires="{expires}",'
#         f'headers="(created) (expires) digest",signature="{signature}"'
#     )
#     return header


# Prepare dynamic fields
request_id = "c72a9d06-d7a5-41e0-a890-4a6e72fe35cc"
timestamp_now = get_timestamp()
valid_from = timestamp_now
valid_until = get_valid_until()

# Final payload
payload = {
    "context": {
        "operation": {
            "ops_no": 1
        }
    },
    "message": {
        "request_id": request_id,
        "timestamp": timestamp_now,
        "entity": {
            "gst": {
                "legal_entity_name": "BANCWISE TECHNOLOGIES LLP",
                "business_address": "51/1702, First Floor, Civil Lane Road, West Fort, Thrissur - Kerala -680006, IN",
                "city_code": ["std:487"],
                "gst_no": "32ABDFB1579P1Z6"
            },
            "pan": {
                "name_as_per_pan": "BANCWISE TECHNOLOGIES LLP",
                "pan_no": "ABDFB1579P",
                "date_of_incorporation": "10/06/2024"
            },
            "name_of_authorised_signatory": "SIJO PAUL E",
            "address_of_authorised_signatory": "2/1384, Plot No 326, 15th Street, Harinagar, P O Punkunnam, Thrissur- 680002, Kerala, India",
            "email_id": "sijo.paul@flashfund.in",
            "mobile_no": 9995103430,
            "country": "IND",
            "subscriber_id": SUBSCRIBER_ID,
            "unique_key_id": UNIQUE_KEY_ID,
            "callback_url": "/",
            "key_pair": {
                "signing_public_key": SIGNING_PUBLIC_KEY,
                "encryption_public_key": ENCRYPTION_PUBLIC_KEY,
                "valid_from": valid_from,
                "valid_until": valid_until
            }
        },
        "network_participant": [
            {
                "subscriber_url": "/",
                "domain": "ONDC:FIS14",
                "type": "buyerApp",
                "msn": False,
                "city_code": ["std:487"]
            }
        ]
    }
}

# Convert to JSON and sign
json_payload = json.dumps(payload, separators=(',', ':'))
authorization_header =  create_authorisation_header(json_payload, SUBSCRIBER_ID, UNIQUE_KEY_ID, SIGNING_PRIVATE_KEY_BASE64)

headers = {
            "Content-Type": "application/json",
            "Authorization": authorization_header,
            "X-Gateway-Authorization": os.getenv("SIGNED_UNIQUE_REQ_ID", ""),
            "X-Gateway-Subscriber-Id": os.getenv("SUBSCRIBER_ID")
        }


# Make the request
response = requests.post(
    "https://preprod.registry.ondc.org/ondc/subscribe",
    headers=headers,
    data=json_payload
)

# Output result
print(f"Status Code: {response.status_code}")
print("Response:")
print(response.text)
