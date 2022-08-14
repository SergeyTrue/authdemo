import base64
import hmac
import hashlib
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "c8d8f3baf7cba67f6f17444a15bd8ee051cb6f804139c2aa2b4e33d223d51206"
PASSWORD_SALT = "823dffc5c83a9be966611f1b27fea7bab255a2b10307fdf92036ea00732b10d4"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные"""
    return hmac.new(
            SECRET_KEY.encode(),
            msg=data.encode(),
            digestmod=hashlib.sha256
            ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    
    
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() ).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    print(f'password hash: {password_hash}\nstored password hash: {stored_password_hash}')
    return password_hash == stored_password_hash


users = {
        "alexey@user.com": {
            "name": "Сергей!",
            "password": "5ee85c605f5b40df3e705a1051164012f3f45901c2ecac252609df510f596d35",
            "balance": 100_000
        },
        "petr@user.com":{
            "name": "Пётр",
            "password": "bad0199cecf64fbd603ccbfe21e08569319c14aba2a7356a8b01e98ecdbaa48a",
            "balance": 555_555
        }
    }


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс {users[valid_username]['balance']}",
            media_type="text/html")


@app.post("/login")
def process_login_page(data:  dict = Body(...)):
    print('data is: ', data)
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
                json.dumps({
                    "success": False,
                    "message": "Я вас не знаю!"
                    }), 
                media_type="application/json")

    response = Response(
            json.dumps({
                "success": True,
                "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
            }), 
            media_type="appication/json")
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
            sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
