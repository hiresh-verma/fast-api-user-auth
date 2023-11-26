import hashlib
import random
from datetime import datetime, timedelta
from random import randbytes

from bson.objectid import ObjectId
from fastapi import APIRouter, Request, Response, status, Depends, HTTPException
from pydantic import EmailStr

from app import oauth2
from app.database import User, Otp
from app.serializers.userSerializers import user_entity, user_response_entity
from .. import schemas, utils
from app.oauth2 import AuthJWT
from ..config import settings
from ..email import Email
from app.utils import auth

router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


@router.post('/register', status_code=status.HTTP_201_CREATED)
async def create_user(payload: schemas.CreateUserSchema, request: Request):
    # Check if user already exist
    user = User.find_one({'email': payload.email.lower()})
    is_verified = user.get('verified')

    if user and is_verified:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail='Account already exist')

    if not user:
        # Compare password and passwordConfirm
        if payload.password != payload.passwordConfirm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

        #  Hash the password
        payload.password = utils.hash_password(payload.password)
        del payload.passwordConfirm

        payload.role = 'user'
        payload.verified = False
        payload.email = payload.email.lower()
        payload.created_at = datetime.utcnow()
        payload.updated_at = payload.created_at

        result = User.insert_one(payload.dict())
        new_user = User.find_one({'_id': result.inserted_id})

        try:

            auth.handle_send_otp(new_user)
            # Otp.find_one_and_update({"_id": result.inserted_id}, {
            #     "$set": {"verification_code": verification_code, "updated_at": datetime.utcnow()}})
            #
            # url = f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/verify/email/{token.hex()}"
            # await Email(user_entity(new_user), url, [EmailStr(payload.email)]).send_verification_code()

        except HTTPException as exc:
            raise exc

        except Exception as error:
            User.find_one_and_update({"_id": result.inserted_id}, {
                "$set": {"verification_code": None, "updated_at": datetime.utcnow()}})
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail='There was an error sending email please try again')

        return {'status': 'success', 'message': 'Verification token successfully sent to your email'}

    else:
        auth.handle_send_otp(user)

        # try:
        #     otp = random.randint(10000, 99999)
        #
        #     User.update({"$set": {"verification_code": verification_code, "updated_at": datetime.utcnow()}})
        #
        #     url = f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/verify/email/{token.hex()}"
        #     await Email(user_entity(User), url, [EmailStr(payload.email)]).send_verification_code()
        # except Exception as error:
        #     User.update({"$set": {"verification_code": None, "updated_at": datetime.utcnow()}})
        #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        #                         detail='There was an error sending email please try again')


@router.get('/verify/email/{token}')
def verify_me(token: str):
    hashed_code = hashlib.sha256()
    hashed_code.update(bytes.fromhex(token))
    verification_code = hashed_code.hexdigest()
    result = User.find_one_and_update({"verification_code": verification_code}, {
        "$set": {"verification_code": None, "verified": True, "updated_at": datetime.utcnow()}}, new=True)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Invalid verification code or account already verified')
    return {
        "status": "success",
        "message": "Account verified successfully"
    }


@router.post('/login')
def login(payload: schemas.LoginUserSchema, response: Response, Authorize: AuthJWT = Depends()):
    # Check if the user exist
    db_user = User.find_one({'email': payload.email.lower()})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')
    user = user_entity(db_user)

    # Check if user verified his email
    if not user['verified']:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Please verify your email address')

    # Check if the password is valid
    if not utils.verify_password(payload.password, user['password']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # Create access token
    access_token = Authorize.create_access_token(
        subject=str(user["id"]), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))

    # Create refresh token
    refresh_jwt_token = Authorize.create_refresh_token(
        subject=str(user["id"]), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN))

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_jwt_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # Send both access
    return {'status': 'success', 'access_token': access_token}


@router.get('/refresh')
def refresh_token(response: Response, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_refresh_token_required()

        user_id = authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')
        user = user_entity(User.find_one({'_id': ObjectId(str(user_id))}))
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='The user belonging to this token no logger exist')
        access_token = authorize.create_access_token(
            subject=str(user["id"]), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
    return {'access_token': access_token}


@router.get('/logout', status_code=status.HTTP_200_OK)
def logout(response: Response, authorize: AuthJWT = Depends(), _user_id: str = Depends(oauth2.require_user)):
    authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}
