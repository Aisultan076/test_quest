from pydantic import BaseModel

USERS = {
    "admin": "123456",
    "user": "password"
}


class LoginData(BaseModel):
    username: str
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str


class RefreshRequest(BaseModel):
    refresh_token: str
