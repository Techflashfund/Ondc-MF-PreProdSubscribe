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


import base64
from nacl.signing import SigningKey
from nacl.bindings import crypto_sign_ed25519_sk_to_seed

# Base64 encoded full private key (private+public)
private_key_base64 = "GBiAwaWGw6og3QVKgzemriesOhsBnmfKSb+gz+JWOPzlXhhiNXxwEHXrEHgnx6MH+zlOXG1dhEK8hNkHcebUjg=="

# The request_id you will use in payload
request_id ="c72a9d06-d7a5-41e0-a890-4a6e72fe35cc" 

# Decode and get the 32 bytes seed
private_key_bytes = base64.b64decode(private_key_base64)
seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
signing_key = SigningKey(seed)

# Sign the request_id
signed = signing_key.sign(request_id.encode())

# Base64 encode the signature
signature_base64 = base64.b64encode(signed.signature).decode()

print("SIGNED_UNIQUE_REQ_ID =", signature_base64)
