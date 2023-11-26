import random
from datetime import datetime, timedelta

from fastapi import HTTPException, status

import app.constants as constants
from app.database import Otp
from app.schemas import OtpSchema


def validate_otp_send(otp_obj: OtpSchema) -> bool:
    current_time = datetime.utcnow()

    if current_time < otp_obj.retry_after:
        time_difference = otp_obj.retry_after - current_time
        minutes_remaining = (time_difference.total_seconds() // 60) % 60
        seconds_remaining = time_difference.total_seconds() % 60

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'Please Wait for {int(minutes_remaining)} minutes and {int(seconds_remaining)} '
                                   f'seconds before attempting to request another OTP')

    if otp_obj.unsuccessful_attempts == 5:
        time_difference = otp_obj.expires_after - current_time
        hours_remaining = time_difference.total_seconds() // 3600
        minutes_remaining = (time_difference.total_seconds() // 60) % 60
        seconds_remaining = time_difference.total_seconds() % 60

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'Too many incorrect OTP attempts. Your account has been temporarily locked for '
                                   f'security purposes. You can request another OTP in {int(hours_remaining)} hou'
                                   f'rs, {int(minutes_remaining)} minutes and {int(seconds_remaining)} seconds. '
                                   f'If you need immediate assistance, '
                                   f'please contact support')

    if otp_obj.retries == 5:
        time_difference = otp_obj.expires_after - current_time
        hours_remaining = time_difference.total_seconds() // 3600
        minutes_remaining = (time_difference.total_seconds() // 60) % 60
        seconds_remaining = time_difference.total_seconds() % 60

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'You have exceeded the maximum number of OTP retries. For security reasons, '
                                   f'please wait for {int(hours_remaining)} hours, {int(minutes_remaining)} minutes '
                                   f'and {int(seconds_remaining)} seconds before trying again '
                                   f'or contact support for assistance.')

    if otp_obj.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=constants.ERROR_OTP_ALREADY_VERIFIED)

    return True


def handle_send_otp(user):
    otp_obj = Otp.find_one({'email': user.get('email')})

    if otp_obj:
        otp_payload = OtpSchema(**otp_obj)
        validate_otp_send(otp_payload)

        otp_payload.otp = random.randint(10000, 99999)
        otp_payload.updated_at = datetime.utcnow()
        otp_payload.retry_after = datetime.utcnow() + timedelta(minutes=5)
        otp_payload.retries += 1

        Otp.find_one_and_update({"_id": otp_obj.get('_id')}, {
            "$set": otp_payload.dict()})

        # send otp here
    else:
        otp_payload = OtpSchema(email=user.get('email'))

        otp_payload.updated_at = otp_payload.created_at

        otp_obj = Otp.insert_one(otp_payload.dict())

        # send otp here
