# ws_manager.py
from typing import Dict
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active: Dict[int, WebSocket] = {}

    async def connect(self, device_id: int, ws: WebSocket):
        await ws.accept()
        self.active[device_id] = ws

    def disconnect(self, device_id: int):
        self.active.pop(device_id, None)

    async def push(self, device_id: int, message: dict) -> bool:
        ws = self.active.get(device_id)
        if not ws:
            return False
        await ws.send_json(message)
        return True

manager = ConnectionManager()