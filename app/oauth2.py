import base64
from typing import List
from fastapi import Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from bson.objectid import ObjectId

from app.serializers.userSerializers import user_entity

from .database import User
from .config import settings


class Settings(BaseModel):
    auth_jwt_algorithm: str = settings.JWT_ALGORITHM
    auth_jwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    auth_jwt_token_location: set = {'cookies', 'headers'}
    auth_jwt_access_cookie_key: str = 'access_token'
    auth_jwt_refresh_cookie_key: str = 'refresh_token'
    auth_jwt_cookie_csrf_protect: bool = False
    auth_jwt_public_key: str = settings.JWT_PUBLIC_KEY
    auth_jwt_private_key: str = settings.JWT_PRIVATE_KEY


@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def require_user(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        user_id = authorize.get_jwt_subject()
        user = user_entity(User.find_one({'_id': ObjectId(str(user_id))}))

        if not user:
            raise UserNotFound('User no longer exist')

        if not user["verified"]:
            raise NotVerified('You are not verified')

    except Exception as e:
        error = e.__class__.__name__
        print(error)
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='You are not logged in')
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='User no longer exist')
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')
    return user_id
