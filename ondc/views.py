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


import os
import json
import base64
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


ONDC_PUBLIC_KEY_BASE64 = "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the shared secret using HKDF-SHA256.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ONDC Encryption',
    ).derive(shared_secret)


def decrypt_challenge(encrypted_challenge: str, shared_key: bytes) -> str:
    decoded = base64.b64decode(encrypted_challenge)
    iv = decoded[:12]
    tag = decoded[-16:]
    ciphertext = decoded[12:-16]

    aes_key = derive_aes_key(shared_key)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    return decrypted.decode('utf-8')


@csrf_exempt
def on_subscribe(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=400)

    try:
        data = json.loads(request.body)
        encrypted_challenge = data.get("challenge")
        if not encrypted_challenge:
            return JsonResponse({"error": "Challenge not found"}, status=400)

        # Load Encryption Private Key (X25519) from base64 DER
        encryption_private_key_b64 = os.getenv("Encryption_Privatekey")
        if not encryption_private_key_b64:
            return JsonResponse({"error": "Encryption private key not configured"}, status=500)

        encryption_private_key_der = base64.b64decode(encryption_private_key_b64)
        encryption_private_key = serialization.load_der_private_key(
            encryption_private_key_der,
            password=None,
        )
        if not isinstance(encryption_private_key, X25519PrivateKey):
            return JsonResponse({"error": "Encryption private key is not X25519"}, status=500)

        # Load ONDC public key DER and convert to X25519PublicKey
        ondc_pub_der = base64.b64decode(ONDC_PUBLIC_KEY_BASE64)
        ondc_pub_obj = serialization.load_der_public_key(ondc_pub_der)
        ondc_pub_raw = ondc_pub_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ondc_public_key = X25519PublicKey.from_public_bytes(ondc_pub_raw)

        # Derive shared secret key using X25519 key exchange
        shared_key = encryption_private_key.exchange(ondc_public_key)

        # Decrypt challenge
        decrypted_challenge = decrypt_challenge(encrypted_challenge, shared_key)

        # Return decrypted challenge as 'answer'
        return JsonResponse({"answer": decrypted_challenge})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": f"Exception: {str(e)}"}, status=500)

