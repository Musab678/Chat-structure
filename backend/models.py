# models.py
from sqlalchemy import (
    Column, BigInteger, Integer, String, LargeBinary, Enum,
    TIMESTAMP, ForeignKey, UniqueConstraint, func
)
from sqlalchemy.orm import declarative_base
import enum

Base = declarative_base()

class DeviceLogEvent(str, enum.Enum):
    enroll = "enroll"
    revoke = "revoke"

class Device(Base):
    __tablename__ = "devices"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    identity_pubkey = Column(LargeBinary(32), nullable=False)   # Ed25519/X25519 pub
    registration_id = Column(Integer, nullable=False)
    label = Column(String(120))
    enrolled_at = Column(TIMESTAMP, server_default=func.now())
    revoked_at = Column(TIMESTAMP, nullable=True)
    last_seen_at = Column(TIMESTAMP, nullable=True)
    __table_args__ = (UniqueConstraint("user_id", "registration_id"),)


class DeviceAttestation(Base):
    __tablename__ = "device_attestations"
    subject_device_id = Column(BigInteger, ForeignKey("devices.id"), primary_key=True)
    signer_device_id = Column(BigInteger, ForeignKey("devices.id"), primary_key=True)
    signature = Column(LargeBinary(64), nullable=False)
    signed_at = Column(BigInteger, nullable=False)  # unix ms


class DeviceLog(Base):
    __tablename__ = "device_log"
    seq = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    event = Column(Enum(DeviceLogEvent), nullable=False)
    device_id = Column(BigInteger, nullable=False)
    payload = Column(LargeBinary(512), nullable=False)
    prev_hash = Column(LargeBinary(32), nullable=False)
    entry_hash = Column(LargeBinary(32), nullable=False)


class SignedPreKey(Base):
    __tablename__ = "signed_prekeys"
    device_id = Column(BigInteger, ForeignKey("devices.id"), primary_key=True)
    key_id = Column(Integer, primary_key=True)
    pubkey = Column(LargeBinary(33), nullable=False)
    signature = Column(LargeBinary(64), nullable=False)


class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"
    device_id = Column(BigInteger, ForeignKey("devices.id"), primary_key=True)
    key_id = Column(Integer, primary_key=True)
    pubkey = Column(LargeBinary(33), nullable=False)


class Envelope(Base):
    __tablename__ = "envelopes"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    dest_device_id = Column(BigInteger, nullable=False, index=True)
    sender_device_id = Column(BigInteger, nullable=False)
    envelope_type = Column(Integer, nullable=False)  # 1=prekey msg, 2=ratchet msg
    ciphertext = Column(LargeBinary(8192), nullable=False)
    server_ts = Column(BigInteger, nullable=False)