import os
import base64
import json
import nacl.public
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .cryptic_utils import decrypt


# Load from environment variables
SIGNED_UNIQUE_REQ_ID = os.environ.get("SIGNED_UNIQUE_REQ_ID")
print(SIGNED_UNIQUE_REQ_ID)
ENCRYPTION_PRIVATE_KEY_BASE64 = os.environ.get("Encryption_Privatekey")

# ONDC's Staging Public Key (constant)
ONDC_PUBLIC_KEY_BASE64="MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q="

def ondc_site_verification(request):
    return HttpResponse(f"""
    <html>
        <head>
            <meta name='ondc-site-verification' content='isk12DbSMBYmeCM+9u0MqQpNKdsNGujBN7PRTeclWkT5DEZYG8oY1J6oI/zP1vr91wOhDjpw1bu+uCmm5HWEAA==' />
        </head>
        <body>
            ONDC Site Verification Page
        </body>
    </html>
    """, content_type="text/html")


import os
import json
import base64
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ONDC_PUBLIC_KEY_BASE64 = "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="

def decrypt_challenge(encrypted_challenge, shared_key):
    cipher = AES.new(shared_key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_challenge))
    return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

@csrf_exempt
def on_subscribe(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            encrypted_challenge = data.get("challenge")

            # Load encryption private key (correct way)
            encryption_private_key_base64 = os.getenv("Encryption_Privatekey")
            encryption_private_key_bytes = base64.b64decode(encryption_private_key_base64)

            private_key = serialization.load_der_private_key(
                encryption_private_key_bytes,
                password=None
            )

            # Load ONDC public key
            ondc_public_key_bytes = base64.b64decode(ONDC_PUBLIC_KEY_BASE64)
            public_key = serialization.load_der_public_key(ondc_public_key_bytes)

            # Generate shared key
            shared_key = private_key.exchange(public_key)

            # Decrypt the challenge
            decrypted_challenge = decrypt_challenge(encrypted_challenge, shared_key)

            return JsonResponse({"answer": decrypted_challenge})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)
