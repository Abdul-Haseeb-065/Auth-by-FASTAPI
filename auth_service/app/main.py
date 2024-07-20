from fastapi import FastAPI, Depends, HTTPException
from jose import jwt, JWTError 
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated


ALGORITHM = "HS256"
SECRET_KEY = "A very Secure Secret Key"

def create_access_token(subject: str , expires_delta: timedelta) -> str:
    expire = datetime.utcnow() + expires_delta 
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

fake_users_db: dict[str, dict[str, str]] = {

    "abdulhaseeb": {
        "username": "abdulhaseeb",
        "full_name": "Abdul Haseeb ",
        "email": "abdulhaseeb@example.com",
        "password": "abdulhaseebpass",
    },
    "ameenalam": {
        "username": "ameenalam",
        "full_name": "Ameen Alam",
        "email": "ameenalam@example.com",
        "password": "ameenalamsecret",
    },
    "mjunaid": {
        "username": "mjunaid",
        "full_name": "Muhammad Junaid",
        "email": "mjunaid@example.com",
        "password": "mjunaidsecret",
    },
}

@app.get("/")
def read_root():
    return{"Hello": "World"}

    
@app.post("/login")
def login(data_from_user: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]):

    user_in_fake_db = fake_users_db.get(data_from_user.username)
    if user_in_fake_db is None:
        raise HTTPException(status_code=400, detail="Incorrect username")

    if not data_from_user.password == user_in_fake_db["password"]:
        raise HTTPException(status_code=400, detail="Incorrect password")

    access_token_expires = timedelta(minutes=1)

    access_token = create_access_token(
        subject=user_in_fake_db["username"], expires_delta=access_token_expires)

        
    access_token_expiry_minutes = timedelta(minutes=1)

    generated_token = create_access_token(
        subject=data_from_user.username, expires_delta= access_token_expiry_minutes)
    return {"username": data_from_user.username, "access_token": generated_token}

@app.get("/users/all")
def get_all_users(token:Annotated[str,Depends(oauth2_scheme)]):
    # Note: We never return passwords in a real application
    return fake_users_db



@app.get("/get-token")
def get_token(name:str): 
    access_token_expiry_minutes = timedelta(minutes=1)

    print("access_token_expiry_minutes: ", access_token_expiry_minutes)

    generated_token = create_access_token(subject=name, expires_delta= access_token_expiry_minutes)
    return {"access_token": generated_token}


def decode_access_token(access_token: str):
    decoded_jwt = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    return decoded_jwt

@app.get("/decode_token")
def decoding_token(access_token: str):
    try:
        decoded_token_data = decode_access_token(access_token)
        return {"decoded_token": decoded_token_data}
    except JWTError as e:
        return {"error": str(e)}    