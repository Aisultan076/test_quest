from pydantic import BaseModel

USERS = {
    "admin": "123456",
    "user": "password"
}

class LoginData(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
