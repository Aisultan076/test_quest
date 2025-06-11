from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from app.models import LoginData, TokenPair, RefreshRequest
from app.auth import (
    verify_user, create_access_token, create_refresh_token,
    decode_token, logout_token, is_token_blacklisted, REFRESH_TOKENS
)
import jwt

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


@app.post("/login", response_model=TokenPair)
def login(data: LoginData):
    if not data.username or not data.password:
        raise HTTPException(400, "Username and password are required")

    if not verify_user(data.username, data.password):
        raise HTTPException(401, "Invalid credentials")

    access_token = create_access_token(data.username)
    refresh_token = create_refresh_token(data.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/refresh", response_model=TokenPair)
def refresh_token(data: RefreshRequest):
    try:
        payload = decode_token(data.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")

        username = payload["sub"]


        stored_token = REFRESH_TOKENS.get(username)
        if stored_token != data.refresh_token:
            raise HTTPException(401, "Refresh token mismatch")

        new_access_token = create_access_token(username)
        new_refresh_token = create_refresh_token(username)  # Опционально обновлять refresh
        return {"access_token": new_access_token, "refresh_token": new_refresh_token}

    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid refresh token")


@app.get("/protected")
def protected(token: str = Depends(oauth2_scheme)):
    try:
        if is_token_blacklisted(token):
            raise jwt.InvalidTokenError
        payload = decode_token(token)
        return {"message": f"Welcome, {payload['sub']}!"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, detail="Invalid token")


@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    logout_token(token)
    return {"message": "Logged out"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
