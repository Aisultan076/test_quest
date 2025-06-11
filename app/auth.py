from datetime import datetime, timedelta
import jwt
from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from app.models import USERS

BLACKLIST = set()
REFRESH_TOKENS = {}  # {username: refresh_token}


def verify_user(username: str, password: str) -> bool:
    return USERS.get(username) == password


def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token = jwt.encode({"sub": username, "exp": expire, "type": "refresh"}, SECRET_KEY, algorithm=ALGORITHM)
    REFRESH_TOKENS[username] = token
    return token


def logout_token(token: str):
    BLACKLIST.add(token)


def is_token_blacklisted(token: str) -> bool:
    return token in BLACKLIST


def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
