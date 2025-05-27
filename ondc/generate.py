import base64
from nacl.signing import SigningKey
from nacl.bindings import crypto_sign_ed25519_sk_to_seed

# Base64 encoded full private key (private+public)
private_key_base64 = "XqDH+WrscKFZY7YfWU+B/JY3fyC3JFqvtwITfVAJvlOHNyJJVvQSWyP3dR+nt7CMTljYu5F9TfyBS6zm4mhazw=="

# The request_id you will use in payload
request_id = "3c697f83-4651-4a7f-84c8-018248c8c771"  

# Decode and get the 32 bytes seed
private_key_bytes = base64.b64decode(private_key_base64)
seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
signing_key = SigningKey(seed)

# Sign the request_id
signed = signing_key.sign(request_id.encode())

# Base64 encode the signature
signature_base64 = base64.b64encode(signed.signature).decode()

print("SIGNED_UNIQUE_REQ_ID =", signature_base64)