# crypto_utils.py
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ATTEST_PREFIX = b"\x01"      # device-signs-device — never reuse this prefix elsewhere
LOG_HASH_PREFIX = b"\x02"    # domain-separates log hashing from signature hashing

def verify_attestation(signer_pubkey: bytes, subject_pubkey: bytes,
                        user_id: int, timestamp_ms: int, signature: bytes) -> bool:
    msg = (
        ATTEST_PREFIX
        + user_id.to_bytes(8, "big")
        + subject_pubkey
        + timestamp_ms.to_bytes(8, "big")
    )
    try:
        Ed25519PublicKey.from_public_bytes(signer_pubkey).verify(signature, msg)
        return True
    except (InvalidSignature, ValueError):
        return False

def chain_hash(prev_hash: bytes, event: str, device_id: int, payload: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(LOG_HASH_PREFIX)
    h.update(prev_hash)
    h.update(event.encode())
    h.update(device_id.to_bytes(8, "big"))
    h.update(payload)
    return h.digest()

def verify_prekey_signature(identity_pubkey: bytes, prekey_pub: bytes, signature: bytes) -> bool:
    """Signed prekey must be signed by the device's long-term identity key."""
    try:
        Ed25519PublicKey.from_public_bytes(identity_pubkey).verify(signature, prekey_pub)
        return True
    except (InvalidSignature, ValueError):
        return False