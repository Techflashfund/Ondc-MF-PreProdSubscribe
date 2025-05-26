import datetime
from cryptic_utils import hash_message, create_signing_string, sign_response

# Your raw request ID or any message
request_id = "c72a9d06-d7a5-41e0-a890-4a6e72fe35cc"

# Provided values
PRIVATE_KEY = "GBiAwaWGw6og3QVKgzemriesOhsBnmfKSb+gz+JWOPzlXhhiNXxwEHXrEHgnx6MH+zlOXG1dhEK8hNkHcebUjg=="

# Step 1: Create timestamps
created = int(datetime.datetime.now().timestamp())
expires = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())

# Step 2: Hash the request_id
digest = hash_message(request_id)

# Step 3: Create signing string
signing_string = create_signing_string(digest, created, expires)

# Step 4: Sign it
signature = sign_response(signing_string, PRIVATE_KEY)

print("Created:", created)
print("Expires:", expires)
print("Signing String:\n", signing_string)
print("Signature:\n", signature)
