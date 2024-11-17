from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from models import User
from database import SessionLocal, engine
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Annotated

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

origins = [
    'http://localhost:3000',
    '127.0.0.1:8000',
    '0.0.0.0'
]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ['*'],
    allow_headers = ['*'],
)

def get_db():
    db = SessionLocal()
    try : 
        yield db
    finally:
        db.close()

# 비밀번호 해싱 및 검증 작업을 관리하기 passlib 객체, CryptContext 초기화 & bcrypt 해싱 알고리즘을 사용 설정
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

#openssl rand -hex 32
SECRET_KEY = 'f6f656204084e998316161df55892ab6deb4f893b4148d5bf658d640bff08d0d'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token : str
    token_type : str

class UserCreate(BaseModel):
    username : str
    password : str

def get_uesr_by_username(db : Session, username : str):
    return db.query(User).filter(User.username==username).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user=User(username=user.username, hashed_password= hashed_password)
    db.add(db_user)
    db.commit()
    return 'completed'

@app.post('/register')
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_uesr_by_username(db, user.username)
    if db_user :
        raise HTTPException(status_code=400, detail='Username already registered')
    return create_user(db=db, user=user)

def authenticate_user(username : str, password: str, db: Session):
    user = db.query(User).filter(User.username==username).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user

def create_access_token(data:dict, expire_delta : timedelta | None = None): # Token 데이터 하나인 access_token을 만들기 위한 준비작업
    to_encode = data.copy()
    if expire_delta :
        expire = expire_delta + datetime.now(timezone.utc)
    else :
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({'exp' : expire})
    
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM )
    return encode_jwt

@app.post('/token')
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)) -> Token:
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user :
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username ro password',
            headers={'WWW-Authenticate' : 'Bearer'},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data = {'sub' : user.username}, expire_delta=access_token_expires
    )
    return Token(access_token= access_token, token_type='bearer')

def verify_token(token: str = Depends(oauth2_scheme)):
    try :
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username : str = payload.get('sub')
        if username is None :
            raise HTTPException(status_code=403, detail='Token is invalid or expired')
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail='Token is invalid or expired')

@app.get('/verify-token/{token}')
async def verify_user_token(token: str):
    verify_token(token=token)
    return {'message' : 'Token is valid'}