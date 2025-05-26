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
ONDC_PUBLIC_KEY_BASE64="MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="

def ondc_site_verification(request):
    return HttpResponse(f"""
    <html>
        <head>
            <meta name='ondc-site-verification' content='xCSNWinHD3Rz1TMFDmDgy4bmRJX1g+R0GtBRh5SOL82fk4TpzsTwQItJwYR1jwxHX/jrOvkk7CISKxM1s7pUDw==' />
        </head>
        <body>
            ONDC Site Verification Page
        </body>
    </html>
    """, content_type="text/html")


import base64
import os
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ONDC_PUBLIC_KEY_BASE64 = "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="

def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    )
    return hkdf.derive(shared_secret)

def decrypt_challenge(encrypted_challenge, shared_key):
    decoded_data = base64.b64decode(encrypted_challenge)
    iv = decoded_data[:16]
    ciphertext = decoded_data[16:]
    aes_key = derive_aes_key(shared_key)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size).decode('utf-8')

@csrf_exempt
def on_subscribe(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            encrypted_challenge = data.get("challenge")
            if not encrypted_challenge:
                return JsonResponse({"error": "Challenge not found"}, status=400)

            # Load encryption private key (base64 DER)
            encryption_private_key_base64 = os.getenv("Encryption_Privatekey")
            encryption_private_key_bytes = base64.b64decode(encryption_private_key_base64)

            private_key = serialization.load_der_private_key(
                encryption_private_key_bytes,
                password=None
            )

            # Load ONDC public key (base64 DER)
            ondc_public_key_bytes = base64.b64decode(ONDC_PUBLIC_KEY_BASE64)
            public_key = serialization.load_der_public_key(ondc_public_key_bytes)

            # Generate shared key
            shared_key = private_key.exchange(public_key)

            # Decrypt the challenge
            decrypted_challenge = decrypt_challenge(encrypted_challenge, shared_key)

            # Return answer
            return JsonResponse({"answer": decrypted_challenge})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)

