from typing import Dict
from app.models import USERS

BLACKLIST = set()

def verify_user(username: str, password: str) -> bool:
    return USERS.get(username) == password

def logout_token(token: str):
    BLACKLIST.add(token)
