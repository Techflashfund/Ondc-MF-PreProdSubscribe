# import os
# import base64
# import json
# import nacl.public
# from django.http import JsonResponse, HttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from .cryptic_utils import decrypt


# # Load from environment variables
# SIGNED_UNIQUE_REQ_ID = os.environ.get("SIGNED_UNIQUE_REQ_ID")
# print(SIGNED_UNIQUE_REQ_ID)
# ENCRYPTION_PRIVATE_KEY_BASE64 = os.environ.get("Encryption_Privatekey")

# # ONDC's Staging Public Key (constant)
# ONDC_PUBLIC_KEY_BASE64="MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="

# def ondc_site_verification(request):
#     return HttpResponse(f"""
#     <html>
#         <head>
#             <meta name='ondc-site-verification' content='xCSNWinHD3Rz1TMFDmDgy4bmRJX1g+R0GtBRh5SOL82fk4TpzsTwQItJwYR1jwxHX/jrOvkk7CISKxM1s7pUDw==' />
#         </head>
#         <body>
#             ONDC Site Verification Page
#         </body>
#     </html>
#     """, content_type="text/html")


# import os
# import json
# import base64
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt

# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# from Crypto.Cipher import AES


# ONDC_PUBLIC_KEY_BASE64 = "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="


# def derive_aes_key(shared_secret: bytes) -> bytes:
#     """
#     Derive a 256-bit AES key from the shared secret using HKDF-SHA256.
#     """
#     return HKDF(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=None,
#         info=b"ONDC Encryption",
#     ).derive(shared_secret)


# def decrypt_challenge(encrypted_challenge: str, shared_key: bytes) -> str:
#     decoded = base64.b64decode(encrypted_challenge)
#     iv = decoded[:12]
#     tag = decoded[-16:]
#     ciphertext = decoded[12:-16]

#     aes_key = derive_aes_key(shared_key)
#     cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
#     decrypted = cipher.decrypt_and_verify(ciphertext, tag)
#     return decrypted.decode("utf-8")


# @csrf_exempt
# def on_subscribe(request):
#     if request.method != "POST":
#         return JsonResponse({"error": "Invalid request method, POST required"}, status=405)

#     try:
#         data = json.loads(request.body)
#     except Exception:
#         return JsonResponse({"error": "Invalid JSON"}, status=400)

#     encrypted_challenge = data.get("challenge")
#     if not encrypted_challenge:
#         return JsonResponse({"error": "Missing 'challenge' in request body"}, status=400)

#     # Load Encryption Private Key (X25519) from base64 DER env var
#     encryption_private_key_b64 = os.getenv("Encryption_Privatekey")
#     if not encryption_private_key_b64:
#         return JsonResponse({"error": "Encryption private key not configured"}, status=500)

#     try:
#         encryption_private_key_der = base64.b64decode(encryption_private_key_b64)
#         encryption_private_key = serialization.load_der_private_key(
#             encryption_private_key_der, password=None
#         )
#     except Exception:
#         return JsonResponse({"error": "Invalid encryption private key"}, status=500)

#     # Load ONDC public key DER and convert to X25519PublicKey
#     try:
#         ondc_pub_der = base64.b64decode(ONDC_PUBLIC_KEY_BASE64)
#         ondc_pub_obj = serialization.load_der_public_key(ondc_pub_der)
#         ondc_pub_raw = ondc_pub_obj.public_bytes(
#             encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
#         )
#         ondc_public_key = X25519PublicKey.from_public_bytes(ondc_pub_raw)
#     except Exception:
#         return JsonResponse({"error": "Failed to load ONDC public key"}, status=500)

#     try:
#         # Derive shared secret key using X25519 key exchange
#         shared_key = encryption_private_key.exchange(ondc_public_key)

#         # Decrypt challenge using shared key
#         decrypted_challenge = decrypt_challenge(encrypted_challenge, shared_key)
#     except Exception as e:
#         return JsonResponse({"error": f"Decryption failed: {str(e)}"}, status=400)

#     # Return decrypted challenge as answer
#     return JsonResponse({"answer": decrypted_challenge})


import base64
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from nacl.signing import SigningKey
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os

# You can load these from environment variables or settings
REQUEST_ID =  "c72a9d06-d7a5-41e0-a890-4a6e72fe35cc" 
SIGNING_PUBLIC_KEY = os.getenv("Signing_public_key")
SIGNING_PRIVATE_KEY = os.getenv("Signing_private_key")
ONDC_PUBLIC_KEY = os.getenv("Encryption_Publickey")  # Is this ONDC's public key or your encryption public key? Confirm.
ENC_PUBLIC_KEY = os.getenv("Encryption_Publickey")
ENC_PRIVATE_KEY = os.getenv("Encryption_Privatekey")
SUBSCRIBER_ID=os.getenv("SUBSCRIBER_ID")


def sign(signing_key: str, private_key_b64: str) -> str:
    private_key_bytes = base64.b64decode(private_key_b64)
    seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
    signer = SigningKey(seed)
    signed = signer.sign(signing_key.encode('utf-8'))
    signature_b64 = base64.b64encode(signed.signature).decode()
    return signature_b64


def decrypt(enc_public_key_b64: str, enc_private_key_b64: str, cipherstring_b64: str) -> str:
    private_key = serialization.load_der_private_key(
        base64.b64decode(enc_private_key_b64),
        password=None
    )
    public_key = serialization.load_der_public_key(
        base64.b64decode(enc_public_key_b64)
    )
    shared_key = private_key.exchange(public_key)
    cipher = AES.new(shared_key, AES.MODE_ECB)
    ciphertxt = base64.b64decode(cipherstring_b64)
    plaintext = unpad(cipher.decrypt(ciphertxt), AES.block_size).decode('utf-8')
    return plaintext


@csrf_exempt
def on_subscribe(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    challenge = data.get('challenge')
    if not challenge:
        return JsonResponse({"error": "Challenge not found"}, status=400)

    try:
        answer = decrypt(ONDC_PUBLIC_KEY, ENC_PRIVATE_KEY, challenge)
    except Exception as e:
        return JsonResponse({"error": f"Decryption failed: {str(e)}"}, status=400)

    return JsonResponse({"answer": answer})


def verify_html(request):
    signature = sign(REQUEST_ID, SIGNING_PRIVATE_KEY)
    html_content = f'''
    <html>
        <head>
            <meta name="ondc-site-verification" content="{signature}" />
        </head>
        <body>
            ONDC Site Verification Page
        </body>
    </html>
    '''
    return HttpResponse(html_content, content_type='text/html')


def health_check(request):
    return JsonResponse({"status": "healthy", "message": "Hello World!"})
