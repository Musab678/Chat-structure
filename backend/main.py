# main.py
from fastapi import FastAPI
from devices import router as devices_router
from keys import router as keys_router
from ws_routes import router as ws_router
from models import Base
from db import engine

app = FastAPI()
Base.metadata.create_all(bind=engine)  # EDIT: use Alembic migrations in prod, not this

app.include_router(devices_router)
app.include_router(keys_router)
app.include_router(ws_router)