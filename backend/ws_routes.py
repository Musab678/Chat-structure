# ws_routes.py
import time
import base64
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session

from db import SessionLocal
from models import Envelope, Device
from ws_manager import manager

router = APIRouter()


def authenticate_device(token: str, db: Session) -> Device | None:
    # EDIT: replace with a real challenge-response against the device's
    # identity key (per the doc — no stored secrets server-side).
    # For now this is a placeholder: token IS the device_id, for local testing only.
    try:
        device_id = int(token)
    except ValueError:
        return None
    return db.query(Device).filter(
        Device.id == device_id, Device.revoked_at.is_(None)
    ).first()


@router.websocket("/v1/ws")
async def ws_endpoint(websocket: WebSocket, token: str = Query(...)):
    db = SessionLocal()
    device = authenticate_device(token, db)
    if not device:
        await websocket.close(code=4001)
        db.close()
        return

    await manager.connect(device.id, websocket)

    # Update last_seen_at on connect
    device.last_seen_at = time.strftime("%Y-%m-%d %H:%M:%S")
    db.commit()

    # Flush any queued envelopes for this device immediately on connect
    pending = (
        db.query(Envelope)
        .filter(Envelope.dest_device_id == device.id)
        .order_by(Envelope.id)
        .limit(100)
        .all()
    )
    for env in pending:
        await websocket.send_json({
            "type": "envelope",
            "id": env.id,
            "sender_device_id": env.sender_device_id,
            "envelope_type": env.envelope_type,
            "ciphertext": base64.b64encode(env.ciphertext).decode(),
            "server_ts": env.server_ts,
        })

    try:
        while True:
            msg = await websocket.receive_json()
            msg_type = msg.get("type")

            # ---- SEND ----
            if msg_type == "send":
                # {"type":"send","dest_device_id":42,"envelope_type":2,"ciphertext":"<b64>"}
                required = {"dest_device_id", "envelope_type", "ciphertext"}
                if not required.issubset(msg):
                    await websocket.send_json({"type": "error", "reason": "missing_fields"})
                    continue

                dest_id = msg["dest_device_id"]

                # Reject sending to a revoked/unknown device
                dest_device = db.query(Device).filter(
                    Device.id == dest_id, Device.revoked_at.is_(None)
                ).first()
                if not dest_device:
                    await websocket.send_json({"type": "error", "reason": "invalid_destination"})
                    continue

                try:
                    ciphertext = base64.b64decode(msg["ciphertext"])
                except Exception:
                    await websocket.send_json({"type": "error", "reason": "bad_ciphertext_encoding"})
                    continue

                if len(ciphertext) > 8192:
                    await websocket.send_json({"type": "error", "reason": "payload_too_large"})
                    continue

                env = Envelope(
                    dest_device_id=dest_id,
                    sender_device_id=device.id,
                    envelope_type=msg["envelope_type"],
                    ciphertext=ciphertext,
                    server_ts=int(time.time() * 1000),
                )
                db.add(env)
                db.commit()
                db.refresh(env)

                delivered = await manager.push(dest_id, {
                    "type": "envelope",
                    "id": env.id,
                    "sender_device_id": env.sender_device_id,
                    "envelope_type": env.envelope_type,
                    "ciphertext": msg["ciphertext"],
                    "server_ts": env.server_ts,
                })

                # Ack to sender regardless — server accepted and queued it either way
                await websocket.send_json({
                    "type": "send_ack",
                    "envelope_id": env.id,
                    "delivered_live": delivered,
                })

            # ---- ACK (recipient confirms decrypt + local storage) ----
            elif msg_type == "ack":
                # {"type":"ack","envelope_id":91}
                if "envelope_id" not in msg:
                    await websocket.send_json({"type": "error", "reason": "missing_envelope_id"})
                    continue

                deleted = db.query(Envelope).filter(
                    Envelope.id == msg["envelope_id"],
                    Envelope.dest_device_id == device.id,
                ).delete()
                db.commit()

                await websocket.send_json({
                    "type": "ack_confirmed",
                    "envelope_id": msg["envelope_id"],
                    "found": deleted > 0,
                })

            # ---- PING/PONG keepalive ----
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            # ---- Unknown message type ----
            else:
                await websocket.send_json({"type": "error", "reason": "unknown_type"})

    except WebSocketDisconnect:
        manager.disconnect(device.id)
    finally:
        db.close()