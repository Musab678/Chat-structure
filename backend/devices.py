# devices.py
import base64
import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel, field_validator

from db import get_db
from models import Device, DeviceAttestation, DeviceLog, DeviceLogEvent
from crypto_utils import verify_attestation, chain_hash

router = APIRouter(prefix="/v1/devices")

GENESIS_HASH = b"\x00" * 32

class EnrollRequest(BaseModel):
    user_id: int
    identity_pubkey: bytes
    registration_id: int
    label: str | None = None
    # idp_token: str  # EDIT: verify against your real IdP before trusting this call

    @field_validator("identity_pubkey", mode="before")
    @classmethod
    def decode_identity_pubkey(cls, value: str | bytes) -> bytes:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError("identity_pubkey must be valid Base64")
        if len(decoded) != 32:
            raise ValueError("identity_pubkey must decode to exactly 32 bytes")
        return decoded

class AttestRequest(BaseModel):
    signer_device_id: int
    signature: bytes
    timestamp_ms: int

    @field_validator("signature", mode="before")
    @classmethod
    def decode_signature(cls, value: str | bytes) -> bytes:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError("signature must be valid Base64")
        if len(decoded) != 64:
            raise ValueError("signature must decode to exactly 64 bytes")
        return decoded

def _append_log(db: Session, user_id: int, event: DeviceLogEvent,
                 device_id: int, payload: bytes) -> DeviceLog:
    last = (
        db.query(DeviceLog)
        .filter(DeviceLog.user_id == user_id)
        .order_by(desc(DeviceLog.seq))
        .first()
    )
    prev_hash = last.entry_hash if last else GENESIS_HASH
    entry_hash = chain_hash(prev_hash, event.value, device_id, payload)
    row = DeviceLog(user_id=user_id, event=event, device_id=device_id,
                     payload=payload, prev_hash=prev_hash, entry_hash=entry_hash)
    db.add(row)
    return row


@router.post("/enroll")
def enroll_device(req: EnrollRequest, db: Session = Depends(get_db)):
    # EDIT: verify req.idp_token here. The IdP auth IS the trust root for device 1.
    existing_count = db.query(Device).filter(Device.user_id == req.user_id).count()

    device = Device(
        user_id=req.user_id,
        identity_pubkey=req.identity_pubkey,
        registration_id=req.registration_id,
        label=req.label,
    )
    db.add(device)
    db.flush()

    if existing_count == 0:
        _append_log(db, req.user_id, DeviceLogEvent.enroll, device.id, payload=req.identity_pubkey)

    db.commit()
    db.refresh(device)

    # EDIT: send device-change notification (email + in-app banner) here
    return {"device_id": device.id,
            "status": "active" if existing_count == 0 else "pending_attestation"}


@router.post("/{device_id}/attest")
def attest_device(device_id: int, req: AttestRequest, db: Session = Depends(get_db)):
    subject = db.query(Device).filter(Device.id == device_id).first()
    if not subject or subject.revoked_at:
        raise HTTPException(404, "device not found or revoked")

    signer = db.query(Device).filter(Device.id == req.signer_device_id).first()
    if not signer or signer.revoked_at:
        raise HTTPException(400, "signer device not found or revoked")
    if signer.user_id != subject.user_id:
        raise HTTPException(400, "signer must belong to same user")

    if not verify_attestation(signer.identity_pubkey, subject.identity_pubkey,
                               subject.user_id, req.timestamp_ms, req.signature):
        raise HTTPException(400, "invalid signature")

    db.add(DeviceAttestation(
        subject_device_id=device_id, signer_device_id=req.signer_device_id,
        signature=req.signature, signed_at=req.timestamp_ms,
    ))
    _append_log(db, subject.user_id, DeviceLogEvent.enroll, device_id,
                payload=subject.identity_pubkey)
    db.commit()
    return {"status": "attested"}


@router.get("/{user_id}")
def list_devices(user_id: int, db: Session = Depends(get_db)):
    devices = db.query(Device).filter(
        Device.user_id == user_id, Device.revoked_at.is_(None)
    ).all()
    result = []
    for d in devices:
        attestations = db.query(DeviceAttestation).filter(
            DeviceAttestation.subject_device_id == d.id
        ).all()
        result.append({
            "device_id": d.id,
            "identity_pubkey": d.identity_pubkey.hex(),
            "label": d.label,
            "enrolled_at": d.enrolled_at,
            "attested_by": [a.signer_device_id for a in attestations],
        })
    return result


@router.post("/{device_id}/revoke")
def revoke_device(device_id: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "not found")
    device.revoked_at = datetime.datetime.utcnow()
    _append_log(db, device.user_id, DeviceLogEvent.revoke, device_id,
                payload=device.identity_pubkey)
    db.commit()
    return {"status": "revoked"}


@router.get("/log/all")
def get_log(since: int = 0, user_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(DeviceLog).filter(DeviceLog.seq > since)
    if user_id:
        q = q.filter(DeviceLog.user_id == user_id)
    rows = q.order_by(DeviceLog.seq).limit(500).all()
    return [
        {"seq": r.seq, "user_id": r.user_id, "event": r.event.value,
         "device_id": r.device_id, "prev_hash": r.prev_hash.hex(),
         "entry_hash": r.entry_hash.hex()}
        for r in rows
    ]