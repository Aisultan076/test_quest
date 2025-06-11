from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
import jwt
from app.auth import verify_user, BLACKLIST, logout_token
from app.models import LoginData, Token
from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


@app.post("/login", response_model=Token)
def login(data: LoginData):
    if not verify_user(data.username, data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": data.username, "exp": expire}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected")
def protected(token: str = Depends(oauth2_scheme)):
    try:
        if token in BLACKLIST:
            raise jwt.InvalidTokenError

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"message": f"Hello, {payload['sub']}!"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    logout_token(token)
    return {"message": "Logged out successfully"}
