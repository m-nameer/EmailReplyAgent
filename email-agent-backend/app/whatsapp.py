import os
import httpx
from fastapi import HTTPException, status
import models

WHATSAPP_URL = os.getenv("WHATSAPP_SERVICE_URL", "http://localhost:8080")

async def get_qr_code(user_id: str):
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(f"{WHATSAPP_URL}/api/whatsapp/{user_id}/qr")
            res.raise_for_status()
            return res.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"WhatsApp service error: {e}")

async def get_status(user_id: str):
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(f"{WHATSAPP_URL}/api/whatsapp/{user_id}/status")
            res.raise_for_status()
            return res.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Status check failed: {e}")

async def send_message(user_id: str, recipient: str, message: str):
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(
                f"{WHATSAPP_URL}/api/whatsapp/{user_id}/send",
                json={"recipient": recipient, "message": message}
            )
            res.raise_for_status()
            return res.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Send failed: {e}")

