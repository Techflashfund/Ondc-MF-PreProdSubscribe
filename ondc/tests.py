# import base64
# import datetime
# from nacl.signing import SigningKey
# from nacl.bindings import crypto_sign_ed25519_sk_to_seed

# # Provided values
# PRIVATE_KEY_BASE64 = "GBiAwaWGw6og3QVKgzemriesOhsBnmfKSb+gz+JWOPzlXhhiNXxwEHXrEHgnx6MH+zlOXG1dhEK8hNkHcebUjg=="
# request_id = "c72a9d06-d7a5-41e0-a890-4a6e72fe35cc"

# # Decode private key and generate signing key
# private_key_bytes = base64.b64decode(PRIVATE_KEY_BASE64)
# seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
# signing_key = SigningKey(seed)

# # Sign the plain request_id
# signed = signing_key.sign(request_id.encode("utf-8"))
# signature = base64.b64encode(signed.signature).decode("utf-8")

# print("Signature for HTML meta tag:\n", signature)


import os
import base64
import json
from django.test import TestCase, Client
from django.urls import reverse
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Assume your view is mapped to url name 'on_subscribe'
# If not, replace reverse('on_subscribe') with your actual URL path

def derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ONDC Encryption",
    ).derive(shared_secret)

def encrypt_challenge(plaintext: str, shared_key: bytes) -> str:
    aes_key = derive_aes_key(shared_key)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    encrypted = cipher.nonce + ciphertext + tag
    return base64.b64encode(encrypted).decode('utf-8')

class OnSubscribeViewTest(TestCase):
    def setUp(self):
        self.client = Client()

        # Generate private and public keys for test
        self.priv_key = X25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()

        # Serialize private key to base64 DER (simulate env var)
        priv_bytes = self.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.priv_key_b64 = base64.b64encode(priv_bytes).decode('utf-8')

        # Patch environment variable
        os.environ["Encryption_Privatekey"] = self.priv_key_b64

        # ONDC public key (simulate)
        self.ondc_pub_key = self.pub_key  # For testing, use same pub key as priv_key to keep it simple

    def test_on_subscribe_success(self):
        # Derive shared key (here just self-priv with self-pub for test simplicity)
        shared_key = self.priv_key.exchange(self.ondc_pub_key)

        # Encrypt sample challenge text
        plaintext = "test-challenge-string"
        encrypted_challenge = encrypt_challenge(plaintext, shared_key)

        response = self.client.post(
            '/on_subscribe/',  # Change if your URL is different
            data=json.dumps({"challenge": encrypted_challenge}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("answer", response.json())
        self.assertEqual(response.json()["answer"], plaintext)

    def test_on_subscribe_missing_challenge(self):
        response = self.client.post(
            '/on_subscribe/',
            data=json.dumps({}), 
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_on_subscribe_wrong_method(self):
        response = self.client.get('/on_subscribe/')
        self.assertEqual(response.status_code, 405)
        self.assertIn("error", response.json())
