"""backend/app/routes/auth.py — POST /api/auth/login"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ..auth import verify_credentials, create_token

router = APIRouter()


class LoginPayload(BaseModel):
    username: str
    password: str


@router.post("/api/auth/login")
def login(payload: LoginPayload):
    if not verify_credentials(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(payload.username)
    return {"access_token": token, "token_type": "bearer", "username": payload.username}
