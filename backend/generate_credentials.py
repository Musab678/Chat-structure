import base64
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

USER_ID = 10
TIMESTAMP_MS = int(time.time() * 1000)

signer_private = Ed25519PrivateKey.generate()
subject_private = Ed25519PrivateKey.generate()

signer_public = signer_private.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw,
)

subject_public = subject_private.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw,
)

message = (
    b"\x01"
    + USER_ID.to_bytes(8, "big")
    + subject_public
    + TIMESTAMP_MS.to_bytes(8, "big")
)

signature = signer_private.sign(message)

print("USER_ID:")
print(USER_ID)

print("\nSIGNER_PUBLIC_KEY:")
print(base64.b64encode(signer_public).decode())

print("\nSUBJECT_PUBLIC_KEY:")
print(base64.b64encode(subject_public).decode())

print("\nTIMESTAMP_MS:")
print(TIMESTAMP_MS)

print("\nSIGNATURE:")
print(base64.b64encode(signature).decode())

print("\nSIGNER_PRIVATE_KEY_KEEP_SECRET:")
print(base64.b64encode(
    signer_private.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )
).decode())