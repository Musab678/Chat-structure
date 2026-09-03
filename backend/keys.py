# keys.py
import time
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from db import get_db
from models import Device, SignedPreKey, OneTimePreKey
from crypto_utils import verify_prekey_signature

router = APIRouter(prefix="/v1/keys")

# EDIT: swap this for Redis in prod — in-memory only works single-process
_rate_bucket: dict[tuple, list[float]] = defaultdict(list)
RATE_LIMIT_WINDOW = 60      # seconds
RATE_LIMIT_MAX = 20         # fetches per requester per target user per window

def _check_rate_limit(requester_id: int, target_user_id: int):
    key = (requester_id, target_user_id)
    now = time.time()
    _rate_bucket[key] = [t for t in _rate_bucket[key] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_bucket[key]) >= RATE_LIMIT_MAX:
        raise HTTPException(429, "too many key fetches, slow down")
    _rate_bucket[key].append(now)


class SignedPreKeyIn(BaseModel):
    key_id: int
    pubkey: bytes       # 33 bytes
    signature: bytes    # 64 bytes, signed by the device's identity key

class OneTimePreKeyIn(BaseModel):
    key_id: int
    pubkey: bytes

class TopUpRequest(BaseModel):
    device_id: int
    signed_prekey: SignedPreKeyIn | None = None   # rotate if provided
    one_time_prekeys: list[OneTimePreKeyIn] = []


@router.put("")
def top_up_keys(req: TopUpRequest, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == req.device_id, Device.revoked_at.is_(None)).first()
    if not device:
        raise HTTPException(404, "device not found or revoked")

    if req.signed_prekey:
        if not verify_prekey_signature(device.identity_pubkey, req.signed_prekey.pubkey,
                                        req.signed_prekey.signature):
            raise HTTPException(400, "signed prekey signature invalid")
        db.merge(SignedPreKey(
            device_id=device.id, key_id=req.signed_prekey.key_id,
            pubkey=req.signed_prekey.pubkey, signature=req.signed_prekey.signature,
        ))

    for otpk in req.one_time_prekeys:
        db.merge(OneTimePreKey(device_id=device.id, key_id=otpk.key_id, pubkey=otpk.pubkey))

    db.commit()
    return {"status": "ok", "one_time_prekeys_added": len(req.one_time_prekeys)}


@router.get("/count")
def key_count(device_id: int, db: Session = Depends(get_db)):
    count = db.query(OneTimePreKey).filter(OneTimePreKey.device_id == device_id).count()
    return {"device_id": device_id, "one_time_prekeys_remaining": count}


@router.get("/{user_id}")
def fetch_key_bundle(user_id: int, requester_id: int, db: Session = Depends(get_db)):
    # requester_id: EDIT — pull this from the authenticated caller, don't trust a query param
    _check_rate_limit(requester_id, user_id)

    devices = db.query(Device).filter(Device.user_id == user_id, Device.revoked_at.is_(None)).all()
    if not devices:
        raise HTTPException(404, "user has no active devices")

    bundles = []
    for d in devices:
        spk = db.query(SignedPreKey).filter(SignedPreKey.device_id == d.id).first()
        if not spk:
            continue  # device hasn't published a signed prekey yet — skip it

        # consume ONE one-time prekey, if available, then delete it — never reused
        otpk = db.query(OneTimePreKey).filter(OneTimePreKey.device_id == d.id).first()
        otpk_out = None
        if otpk:
            otpk_out = {"key_id": otpk.key_id, "pubkey": otpk.pubkey.hex()}
            db.delete(otpk)

        bundles.append({
            "device_id": d.id,
            "registration_id": d.registration_id,
            "identity_pubkey": d.identity_pubkey.hex(),
            "signed_prekey": {"key_id": spk.key_id, "pubkey": spk.pubkey.hex(),
                               "signature": spk.signature.hex()},
            "one_time_prekey": otpk_out,   # null if exhausted -> weaker fwd secrecy for this session
        })

    db.commit()  # persist the OTPK deletions
    return {"user_id": user_id, "devices": bundles}