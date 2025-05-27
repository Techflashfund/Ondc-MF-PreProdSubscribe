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
            <meta name='ondc-site-verification' content='xCSNWinHD3Rz1TMFDmDgy4bmRJX1g+R0GtBRh5SOL82fk4TpzsTwQItJwYR1jwxHX/jrOvkk7CISKxM1s7pUDw==' />
        </head>
        <body>
            ONDC Site Verification Page
        </body>
    </html>
    """, content_type="text/html")
    


# import os
# import json
# import base64
# from django.http import JsonResponse, HttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import x25519
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import unpad

# ONDC_PUBLIC_KEY_BASE64 = "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="

# def decrypt_challenge(encrypted_challenge, shared_key):
#     cipher = AES.new(shared_key, AES.MODE_ECB)
#     decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_challenge))
#     return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

# @csrf_exempt
# def on_subscribe(request):
#     if request.method == "POST":
#         try:
#             data = json.loads(request.body)
#             encrypted_challenge = data.get("challenge")

#             # Load encryption private key (correct way)
#             encryption_private_key_base64 = os.getenv("Encryption_Privatekey")
#             encryption_private_key_bytes = base64.b64decode(encryption_private_key_base64)

#             private_key = serialization.load_der_private_key(
#                 encryption_private_key_bytes,
#                 password=None
#             )

#             # Load ONDC public key
#             ondc_public_key_bytes = base64.b64decode(ONDC_PUBLIC_KEY_BASE64)
#             public_key = serialization.load_der_public_key(ondc_public_key_bytes)

#             # Generate shared key
#             shared_key = private_key.exchange(public_key)

#             # Decrypt the challenge
#             decrypted_challenge = decrypt_challenge(encrypted_challenge, shared_key)

#             return JsonResponse({"answer": decrypted_challenge})

#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)

#     return JsonResponse({"error": "Invalid request"}, status=400)


import base64
import json
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from nacl.signing import SigningKey
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Your config - replace these with your real keys or environment variables
REQUEST_ID = "c72a9d06-d7a5-41e0-a890-4a6e72fe35cc"
SIGNING_PUBLIC_KEY = "5V4YYjV8cBB16xB4J8ejB/s5TlxtXYRCvITZB3Hm1I4="
SIGNING_PRIVATE_KEY = "GBiAwaWGw6og3QVKgzemriesOhsBnmfKSb+gz+JWOPzlXhhiNXxwEHXrEHgnx6MH+zlOXG1dhEK8hNkHcebUjg=="
ONDC_PUBLIC_KEY = "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="
ENC_PUBLIC_KEY = "MCowBQYDK2VuAyEAVFXINjXoWGPZ4zshbPwugbm9A932PjH3fey6D3nvOxk="
ENC_PRIVATE_KEY = "MC4CAQAwBQYDK2VuBCIEIAhsMay0cwBEUSdFanNlJ3NlF88YiAUULJ60ueK6wide"


def sign(signing_key, private_key):
    private_key64 = base64.b64decode(private_key)
    seed = crypto_sign_ed25519_sk_to_seed(private_key64)
    signer = SigningKey(seed)
    signed = signer.sign(bytes(signing_key, encoding='utf8'))
    signature = base64.b64encode(signed.signature).decode()
    return signature


def decrypt(enc_public_key, enc_private_key, cipherstring):
    private_key = serialization.load_der_private_key(
        base64.b64decode(enc_private_key),
        password=None
    )
    public_key = serialization.load_der_public_key(
        base64.b64decode(enc_public_key)
    )
    shared_key = private_key.exchange(public_key)
    cipher = AES.new(shared_key, AES.MODE_ECB)
    ciphertxt = base64.b64decode(cipherstring)
    return unpad(cipher.decrypt(ciphertxt), AES.block_size).decode('utf-8')


@csrf_exempt
def on_subscribe(request):
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST allowed")
    try:
        data = json.loads(request.body)
    except Exception as e:
        return JsonResponse({"error": f"Invalid JSON: {str(e)}"}, status=400)
    
    # Debug print/log the incoming request JSON
    print(f"/on_subscribe called :: Request -> {data}")

    try:
        decrypted_answer = decrypt(ONDC_PUBLIC_KEY, ENC_PRIVATE_KEY, data['challenge'])
    except Exception as e:
        return JsonResponse({"error": f"Decryption failed: {str(e)}"}, status=500)

    return JsonResponse({"answer": decrypted_answer})
