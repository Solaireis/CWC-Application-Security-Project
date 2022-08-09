"""
This python file contains all the functions that touches on the MySQL database.
"""
# import python standard libraries
import json
from socket import inet_aton, inet_pton, AF_INET6
from typing import Union, Optional
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from hashlib import sha512
from math import ceil
from base64 import urlsafe_b64decode

# import Flask web application configs
from flask import url_for, current_app, abort

# import third party libraries
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHash
import pymysql.err as MySQLErrors
from pymysql.connections import Connection as MySQLConnection
import requests
from jsonschema import validate

# import local python files
from python_files.classes.Course import CourseInfo
from python_files.classes.User import UserInfo
from python_files.classes.Errors import *
from python_files.classes.Reviews import ReviewInfo, Reviews
from .NormalFunctions import JWTExpiryProperties, generate_id, pwd_has_been_pwned, pwd_is_strong, \
                             symmetric_encrypt, symmetric_decrypt, EC_sign, get_dicebear_image, \
                             send_email, write_log_entry, get_mysql_connection, delete_blob, generate_secure_random_bytes, ExpiryProperties
from python_files.classes.Constants import CONSTANTS
from .VideoFunctions import delete_video

schema = {
    
}

def get_blob_name(url:str="") -> str:
    """
    Get the blob name from the Google Storage API URL.

    Args:
    - url (str): The URL of the blob.
        - E.g. https://storage.cloud.google.com/coursefinity-videos/videos/watame.mp4
            - Will return "videos/watame.mp4"

    Returns:
    - The blob name (str) or a empty string if the url is not a valid Google Storage URL.
    """
    # if (re.fullmatch(CONSTANTS.GOOGLE_STORAGE_URL_REGEX, url)) else ""
    return "/".join(url.split("/")[4:])

def add_session(userID:str, userIP:str="", userAgent:str="") -> str:
    """
    Generate a 32 byte session ID and add it to the database.

    Args:
    - userID (str): The user ID of the use
    - userIP (str): The IP address of the user
    - userAgent (str): The user agent of the user

    Returns:
    - The generated session ID (str)
    """
    # minimum requirement for a session ID length is 16 bytes as stated in OWASP's Session Management Cheatsheet,
    # https://owasp.deteact.com/cheat/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-length
    sessionID = generate_secure_random_bytes(nBytes=32, generateFromHSM=True, returnHex=True)

    sql_operation(table="session", mode="create_session", sessionID=sessionID, userID=userID, userIP=userIP, userAgent=userAgent)
    return sessionID

def generate_limited_usage_jwt_token(
    payload:Union[str, list, dict]="", expiryInfo:Optional[JWTExpiryProperties]=None, 
    limit:Optional[int]=None, encodeTokenFlag:Optional[bool]=True,
    getTokenIDFlag:Optional[bool]=False
) -> Union[str, tuple]:
    """
    Generate a limited usage token and add it to the MySQL database.

    Args:
    - payload (Union[str, list, dict]): The payload of the token.
    - expiryInfo (JWTExpiryProperties, Optional): The expiry information of the token.
    - limit (int, Optional): The usage limit of the token.
    - encodeTokenFlag (bool, Optional): Whether to encode the token or not from this function.
        - Default: True, will return a urlsafe base64 encoded token.
    - getTokenIDFlag (bool, Optional): Whether to get the token ID or not from this function.
        - Default: False, will not get the token ID.
    """
    if (expiryInfo is None and limit is None):
        raise ValueError("Either expiryInfo OR limit must be specified.")

    if (expiryInfo is not None and not isinstance(expiryInfo, JWTExpiryProperties)):
        raise ValueError("Defined expiry information must be a JWTExpiryProperties object.")\

    expiryInfoToStore = None
    if (expiryInfo is not None):
        expiryInfoToStore = expiryInfo.expiryDate.replace(microsecond=0, tzinfo=None)

    tokenID = generate_secure_random_bytes(nBytes=32, generateFromHSM=True, returnHex=True)
    token = EC_sign(payload=payload, b64EncodeData=encodeTokenFlag, expiry=expiryInfo, tokenID=tokenID)
    sql_operation(
        table="limited_use_jwt", mode="add_jwt", tokenID=tokenID,
        expiryDate=expiryInfoToStore, limit=limit
    )
    return token if (not getTokenIDFlag) else (token, tokenID)

def get_upload_credentials(courseID:str, teacherID:str) -> Optional[dict]:
    """
    Send a request to VdoCipher to prepare to receive a video.
    Returns the proper credentials to connect with VdoCipher to receive said video.
    Passed to Dropzone as an API call.

    Uses input values derived from a JWT.
    Creates another JWT with videoID, to be passed to server when upload successful (for MySQL).

    Inputs:
    - courseID (str)
    - teacherID (str)

    Outputs (dict):
    {
        'clientPayload': {
            'policy': ... (str),
            'key': ... (str),
            'x-amz-signature': ... (str),
            'x-amz-algorithm': ... (str),
            'x-amz-date': ... (str),
            'x-amz-credential': ... (str),
            'uploadLink': ... (str),
            'successUrl': ... (str)
    }
    """
    data = json.loads(requests.put(
        url="https://dev.vdocipher.com/api/videos",
        headers={
            "Authorization": f"Apisecret {current_app.config['SECRET_CONSTANTS'].VDOCIPHER_SECRET}"
        },
        params={
            "title": f"Course {courseID}",
            "folderId": "root"
        }
    )
    .text)

    if data.get("message") is not None: # E.g. {'message': 'You have reached the trial limit of 4 videos. 
                                        # Either remove the previously uploaded videos or 
                                        # subscribe to our premium plans to unlock the video limit.'}
        print(data.get("message"))
        #TODO: Log error
        return None

    payload = data["clientPayload"]

    expiryInfo = JWTExpiryProperties(activeDuration=300)
    jwtToken = generate_limited_usage_jwt_token(
        payload={
            "teacherID": teacherID,
            "courseID": courseID,
            "videoPath": data["videoId"],
            "dateCreated":  datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        expiryInfo=expiryInfo,
        limit=1
    )

    payload["successUrl"] = url_for("teacherBP.uploadSuccess", jwtToken=jwtToken)
    print(payload)
    return payload

def send_verification_email(email:str="", username:Optional[str]=None, userID:str="") -> None:
    """
    Send an email to the user to verify their account.

    Note: The JWT will expire in 3 days.

    Args:
    - email (str): The email of the user.
    - username (str): The username of the user.
    - userID (str): The user ID of the user.
    """
    # verify email token will be valid for a week
    expiryInfo = JWTExpiryProperties(
        datetimeObj=datetime.now().astimezone(tz=ZoneInfo("Asia/Singapore")) + timedelta(days=3)
    )
    token = generate_limited_usage_jwt_token(
        payload={"email": email, "userID": userID},
        expiryInfo=expiryInfo,
        limit=1
    )
    htmlBody = (
        f"Welcome to CourseFinity!<br>",
        "Please click the link below to verify your email address:",
        f"<a href='{CONSTANTS.CUSTOM_DOMAIN}{url_for('generalBP.verifyEmail', token=token)}' style='{current_app.config['CONSTANTS'].EMAIL_BUTTON_STYLE}' target='_blank'>Verify Email</a>"
    )
    send_email(to=email, subject="Please verify your email!", body="<br>".join(htmlBody), name=username)

def send_unlock_locked_acc_email(email:str="", userID:str="") -> None:
    """
    Send an email to the user to unlock their account.

    Note: The JWT will expire in 30 minutes.

    Args:
    - email (str): The email of the user.
    - userID (str): The user ID of the user.
    """
    expiryInfo = JWTExpiryProperties(
        datetimeObj=datetime.now().astimezone(tz=ZoneInfo("Asia/Singapore")) + timedelta(minutes=30)
    )
    token = generate_limited_usage_jwt_token(
        payload={"email": email, "userID": userID},
        expiryInfo=expiryInfo,
        limit=1
    )
    htmlBody = (
        "Your account has been locked due to too many failed login attempts.<br>",
        "Just in case that it was you, you can unlock your account by clicking the button below.",
        "Otherwise, we suggest that you consider changing your password after unlocking your account and logging in.<br>",
        "To change password:",
        f"{current_app.config['CONSTANTS'].CUSTOM_DOMAIN}{url_for('userBP.updatePassword')}<br>",
        "Please click the link below to unlock your account:",
        f"<a href='{current_app.config['CONSTANTS'].CUSTOM_DOMAIN}{url_for('guestBP.unlockAccount', token=token)}' style='{current_app.config['CONSTANTS'].EMAIL_BUTTON_STYLE}' target='_blank'>Unlock Account</a>",
        "Note: This link will expire in 30 minutes as the account locked timeout will last for 30 minutes."
    )
    send_email(to=email, subject="Unlock your account!", body="<br>".join(htmlBody))

def get_image_path(userID:str, returnUserInfo:bool=False, getCart:Optional[bool]=False) -> Union[str, UserInfo]:
    """
    Returns the image path for the user.

    If the user does not have a profile image uploaded, it will return a dicebear url.
    Else, it will return the relative path of the user's profile image.

    If returnUserInfo is True, it will return a tuple of the user's record.

    Args:
    - userID (str): The user's ID
    - returnUserInfo (bool): If True, it will return a tuple of the user's record.
    - getCart (bool, Optional): If True, it will also return the user's cart items.
        - Default: False, will not return the user's cart items.

    Returns:
    - The image path (str) only if returnUserInfo is False
    - The UserInfo object with the profile image path in the object if returnUserInfo is True
    """
    userInfo = sql_operation(table="user", mode="get_user_data", userID=userID, getCart=getCart)

    # Since the admin user will not have an upload profile image feature,
    # return an empty string for the image profile src link if the user is the admin user.
    if (userInfo.role == "Admin"):
        userInfo.profileImage = "https://storage.googleapis.com/coursefinity/user-profiles/default.png"
        return userInfo.profileImage if (not returnUserInfo) else userInfo

    imageSrcPath = userInfo.profileImage
    return imageSrcPath if (not returnUserInfo) else userInfo

def format_user_info(userInfo:tuple) -> UserInfo:
    """
    Format the user's information to be returned to the client.

    Args:
    - userInfo (tuple): The user's tuple matched from a database query.

    Returns:
    - UserInfo object with the formatted user information.
    """
    userProfile = get_dicebear_image(userInfo[2]) if (userInfo[6] is None) else userInfo[6]
    return UserInfo(tupleData=userInfo, userProfile=userProfile)

def sql_operation(table:str=None, mode:str=None, **kwargs) -> Union[str, list, tuple, bool, dict, None]:
    """
    Connects to the database and returns the connection object

    Args:
    - table: The table to connect to ("course", "user")
    - mode: The mode to use ("insert", "edit", "login", etc.)
    - kwargs: The keywords to pass into the respective sql operation functions

    Returns the returned value from the SQL operation.
    """
    returnValue = con = None
    try:
        con = get_mysql_connection(debug=CONSTANTS.DEBUG_MODE, user="coursefinity")
    except (MySQLErrors.OperationalError):
        print("Fatal Error: Database Not Found...")
        if (CONSTANTS.DEBUG_MODE):
            raise Exception("Database Not Found... Please initialise the database.")
        else:
            write_log_entry(
                logMessage="MySQL server has no database, \"coursefinity\"! The web application will go to maintanence mode until the database is created.",
                severity="EMERGENCY"
            )
            current_app.config["MAINTENANCE_MODE"] = True
            return None

    with con:
        try:
            if (table == "user"):
                returnValue = user_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "course"):
                returnValue = course_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "session"):
                returnValue = session_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "login_attempts"):
                returnValue = login_attempts_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "2fa_token"):
                returnValue = twofa_token_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "user_ip_addresses"):
                returnValue = user_ip_addresses_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "review"):
                returnValue = review_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "reset_password"):
                returnValue = reset_password_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "limited_use_jwt"):
                returnValue = limited_use_jwt_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "role"):
                returnValue = role_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "recovery_token"):
                returnValue = recovery_token_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "stripe_payments"):
                returnValue = stripe_payments_sql_operation(connection=con, mode=mode, **kwargs)
            elif (table == "cart"):
                returnValue = cart_sql_operation(connection=con, mode=mode, **kwargs)
            else:
                raise ValueError("Invalid table name")
        except (
            MySQLErrors.MySQLError,
            MySQLErrors.Warning,
            MySQLErrors.Error,
            MySQLErrors.InterfaceError,
            MySQLErrors.DatabaseError,
            MySQLErrors.DataError,
            MySQLErrors.OperationalError, 
            MySQLErrors.IntegrityError,
            MySQLErrors.InternalError, 
            MySQLErrors.ProgrammingError,
            MySQLErrors.NotSupportedError,
            KeyError, ValueError
        ) as e:
            # to ensure that the connection is closed even if an error with mysql occurs
            print("Error caught:")
            print(e)
            write_log_entry(
                logMessage=f"Error caught: {e}",
                severity="ERROR"
            )
            abort(500)

    return returnValue

def reset_password_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[str, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the cart_sql_operation function!")

    cur = connection.cursor()
    if (mode == "add_token"):
        expiryDatetime = kwargs["expiryDate"]
        if (isinstance(expiryDatetime, ExpiryProperties)):
            expiryDatetime = expiryDatetime.expiryDate.replace(microsecond=0, tzinfo=None)

        cur.execute(
            "INSERT INTO reset_password (user_id, token, expiry_date) VALUES (%(userID)s, %(token)s, %(expiryDate)s)",
            {"userID": kwargs["userID"], "token": kwargs["token"], "expiryDate": expiryDatetime}
        )
        connection.commit()

    elif (mode == "verify_token"):
        token = symmetric_decrypt(
            ciphertext=urlsafe_b64decode(kwargs["token"]),
            keyID=current_app.config["CONSTANTS"].TOKEN_ENCRYPTION_KEY_ID,
            decode=False
        )
        cur.execute(
            """
            SELECT 
            r.user_id, u.status, t.token
            FROM reset_password AS r 
            INNER JOIN user AS u ON r.user_id=u.id
            LEFT OUTER JOIN twofa_token AS t ON r.user_id=t.user_id
            WHERE r.token = %(token)s AND r.expiry_date >= SGT_NOW();
            """,
            {"token": token}
        )
        matched = cur.fetchone()
        print("Matched:", matched)
        return matched if (matched is not None) else None

    elif (mode == "delete_token"):
        token = symmetric_decrypt(
            ciphertext=urlsafe_b64decode(kwargs["token"]),
            keyID=current_app.config["CONSTANTS"].TOKEN_ENCRYPTION_KEY_ID,
            decode=False
        )
        cur.execute("DELETE FROM reset_password WHERE token = %(token)s", {"token": token})
        connection.commit()

    elif (mode == "delete_token_by_user_id"):
        cur.execute("DELETE FROM reset_password WHERE user_id = %(userID)s", {"userID": kwargs["userID"]})
        connection.commit()

    elif (mode == "delete_all_expired_tokens"):
        cur.execute(
            "DELETE FROM reset_password WHERE expiry_date < SGT_NOW()"
        )
        connection.commit()

    else:
        raise ValueError("Invalid mode in reset_password_sql_operation function!")

def cart_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[bool, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the cart_sql_operation function!")

    cur = connection.cursor()
    if (mode == "check_if_purchased_or_in_cart"):
        courseID = kwargs["courseID"]
        userID = kwargs["userID"]

        cur.execute("SELECT * FROM cart WHERE course_id=%(courseID)s AND user_id=%(userID)s", {"courseID":courseID, "userID":userID})
        isInCart = (cur.fetchone() is not None)

        cur.execute("SELECT * FROM purchased_courses WHERE course_id=%(courseID)s AND user_id=%(userID)s", {"courseID":courseID, "userID":userID})
        isPurchased = (cur.fetchone() is not None)

        return (isInCart, isPurchased)

    else:
        raise ValueError("Invalid mode in cart_sql_operation function!")

def stripe_payments_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[bool, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the stripe_payments_sql_operation function!")

    cur = connection.cursor()
    if mode == "create_payment_session":
        paymentID = kwargs["paymentID"]
        stripePaymentIntent = kwargs["stripePaymentIntent"]
        userID = kwargs["userID"]
        cartcourseIDs = kwargs["cartCourseIDs"]
        createdTime = kwargs["createdTime"]
        amount = kwargs["amount"]

        cur.execute(
            "INSERT INTO stripe_payments (payment_id, user_id, cart_courses, stripe_payment_intent, created_time, amount) VALUES (%(paymentID)s, %(userID)s, %(cartCourseIDs)s, %(stripePaymentIntent)s, %(createdTime)s, %(amount)s)",
            {"paymentID": paymentID, "userID": userID, "cartCourseIDs": cartcourseIDs, "stripePaymentIntent": stripePaymentIntent, "createdTime": createdTime, "amount": amount}
        )
        connection.commit()
        return paymentID

    if mode == "complete_payment_session":
        paymentID = kwargs["paymentID"]
        paymentTime = kwargs["paymentTime"]
        receiptEmail = kwargs["receiptEmail"]

        cur.execute(
            "UPDATE stripe_payments SET payment_time=%(paymentTime)s, receipt_email=%(receiptEmail)s WHERE payment_id = %(paymentID)s",
            {"paymentTime": paymentTime, "receiptEmail": receiptEmail, "paymentID": paymentID}
        )
        connection.commit()

    elif mode == "get_payment_intent":
        paymentID = kwargs["paymentID"]

        cur.execute(
            "SELECT stripe_payment_intent FROM stripe_payments WHERE payment_id = %(paymentID)s",
            {"paymentID": paymentID}
        )
        stripePaymentIntent = cur.fetchone()[0]
        return stripePaymentIntent

    elif mode == "delete_expired_payment_sessions":
        cur.execute("DELETE FROM stripe_payments WHERE TIMESTAMPDIFF(hour, created_time, now()) > 1 AND payment_time IS NULL")

def recovery_token_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[bool, None]:
    """For recovering user's account (from user management)"""
    if (mode is None):
        raise ValueError("You must specify a mode in the recovery_token_sql_operation function!")

    cur = connection.cursor()
    if (mode == "add_token"):
        tokenID = kwargs["tokenID"]
        userID = kwargs["userID"]
        oldUserEmail = kwargs["oldUserEmail"]

        cur.execute(
            "INSERT INTO recovery_token (token_id, user_id, old_user_email) VALUES (%(tokenID)s, %(userID)s, %(oldUserEmail)s)",
            {"tokenID": tokenID, "userID": userID, "oldUserEmail": oldUserEmail}
        )
        connection.commit()

    elif (mode == "check_if_recovering"):
        userID = kwargs["userID"]

        cur.execute(
            "SELECT * FROM recovery_token WHERE user_id = %(userID)s", 
            {"userID": userID}
        )
        return (cur.fetchone() is not None)

    elif (mode == "revoke_token"):
        userID = kwargs["userID"]

        cur.execute("SELECT old_user_email FROM recovery_token WHERE user_id = %(userID)s", {"userID": userID})
        oldUserEmail = cur.fetchone()[0]

        cur.execute("CALL delete_recovery_token(%(userID)s)", {"userID": userID})
        connection.commit()

        cur.execute("UPDATE user SET email = %(oldUserEmail)s, status='Active' WHERE id = %(userID)s", {"oldUserEmail": oldUserEmail, "userID": userID})
        connection.commit()

    else:
        raise ValueError("Invalid mode in the recovery_token_sql_operation function!")

def limited_use_jwt_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[bool, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the limited_use_jwt_sql_operation function!")

    cur = connection.cursor()
    if (mode == "add_jwt"):
        tokenID = kwargs["tokenID"]
        expiryDate = kwargs.get("expiryDate")
        limit = kwargs.get("limit")
        print(limit)
        cur.execute(
            "INSERT INTO limited_use_jwt (id, expiry_date, token_limit) VALUES (%(tokenID)s, %(expiryDate)s, %(tokenLimit)s)",
            {"tokenID": tokenID, "expiryDate": expiryDate, "tokenLimit": limit}
        )
        connection.commit()

    elif (mode == "decrement_limit_after_use"):
        tokenID = kwargs["tokenID"]
        cur.execute(
            "UPDATE limited_use_jwt SET token_limit = token_limit - 1 WHERE id = %(tokenID)s AND token_limit IS NOT NULL AND token_limit > 0",
            {"tokenID": tokenID}
        )
        connection.commit()
        cur.execute(
            "DELETE FROM limited_use_jwt WHERE id = %(tokenID)s AND token_limit IS NOT NULL AND token_limit <= 0",
            {"tokenID": tokenID}
        )
        connection.commit()

    elif (mode == "jwt_is_valid"):
        tokenID = kwargs["tokenID"]
        print("token", tokenID)
        cur.execute(
            "SELECT token_limit FROM limited_use_jwt WHERE id = %(tokenID)s",
            {"tokenID": tokenID}
        )
        matched = cur.fetchone()
        if (matched is None):
            return False

        # Check if the JWT is valid by checking the limit
        # Note: Since if the JWT is limited by the expiry date, it already has an expiry date set in the JWT and 
        # will be checked during the verification of the JWT signature. Hence, we will only check the limit here.
        limit = matched[0]
        # if the limit is defined and is more than 0, then the jwt token is valid
        # if the limit is not defined, then the jwt token is valid 
        # as long as it exists (unlimited usage)
        if (limit is None or limit > 0):
            return True
        return False

    elif (mode == "delete_expired_jwt"):
        # to free up the database if the user did not use the token at all
        # to avoid pilling up the database table with redundant data
        cur.execute("DELETE FROM limited_use_jwt WHERE expiry_date < SGT_NOW() OR token_limit <= 0")
        connection.commit()

    else:
        raise ValueError("Invalid mode in the limited_use_jwt_sql_operation function!")

def user_ip_addresses_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[list, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the user_ip_addresses_sql_operation function!")

    cur = connection.cursor()
    if (mode == "add_ip_address"):
        userID = kwargs["userID"]
        ipAddress = kwargs["ipAddress"]

        # Convert the IP address to binary format
        try:
            ipAddress = inet_aton(ipAddress).hex()
            isIpv4 = True
        except (OSError):
            isIpv4 = False
            ipAddress = inet_pton(AF_INET6, ipAddress).hex()

        cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address, last_accessed, is_ipv4) VALUES (%(userID)s, %(ipAddress)s, SGT_NOW(), %(isIpv4)s)", {"userID":userID, "ipAddress":ipAddress, "isIpv4":isIpv4})
        connection.commit()

    elif (mode == "get_ip_addresses"):
        userID = kwargs["userID"]

        cur.execute("SELECT ip_address FROM user_ip_addresses WHERE user_id = %(userID)s", {"userID":userID})
        returnValue = cur.fetchall()
        ipAddressList = [ipAddress[0] for ipAddress in returnValue]
        return ipAddressList

    elif (mode == "add_ip_address_only_if_unique"):
        userID = kwargs["userID"]
        ipAddress = kwargs["ipAddress"]

        # Convert the IP address to binary format
        try:
            ipAddress = inet_aton(ipAddress).hex()
            isIpv4 = True
        except (OSError):
            isIpv4 = False
            ipAddress = inet_pton(AF_INET6, ipAddress).hex()

        cur.execute("SELECT * FROM user_ip_addresses WHERE user_id = %(userID)s AND ip_address = %(ipAddress)s AND is_ipv4=0", {"userID":userID, "ipAddress":ipAddress})

        if (cur.fetchone() is None):
            cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address, last_accessed, is_ipv4) VALUES (%(userID)s, %(ipAddress)s, SGT_NOW(), %(isIpv4)s)", {"userID":userID, "ipAddress":ipAddress, "isIpv4":isIpv4})
            connection.commit()

    elif (mode == "remove_last_accessed_more_than_10_days"):
        cur.execute("DELETE FROM user_ip_addresses WHERE DATEDIFF(SGT_NOW(), last_accessed) > 10")
        connection.commit()

    else:
        raise ValueError("Invalid mode in the user_ip_addresses_sql_operation function!")

def generate_backup_codes(encrypt:Optional[bool]=False) -> Union[list, bytes]:
    """
    Generate a list of backup codes

    Args:
    - encrypt (bool): Whether to return the list in encrypted format
        - Default: False, will return a list

    Returns:
    - list: A list of backup codes if encrypt is False
    - bytes: A list of backup codes in encrypted format if encrypt is True
    """
    backupCodes = []
    for _ in range(8):
        backupCode = generate_secure_random_bytes(nBytes=8, generateFromHSM=True, returnHex=True)
        formattedBackupCode = "-".join([backupCode[:4], backupCode[4:8], backupCode[8:12], backupCode[12:16]])
        el = (formattedBackupCode, "Active")
        backupCodes.append(el)

    if (encrypt):
        backupCodes = symmetric_encrypt(
            plaintext=json.dumps(backupCodes), 
            keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
        )

    return backupCodes 

def twofa_token_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[bool, str, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the twofa_token_sql_operation function!")

    cur = connection.cursor()
    if (mode == "add_token"):
        token = kwargs["token"]
        userID = kwargs["userID"]
        token = symmetric_encrypt(plaintext=token, keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID)

        try:
            # Try inserting a new data
            cur.execute(
                "INSERT INTO twofa_token (token, user_id, backup_codes_json) VALUES (%(token)s, %(userID)s, %(tokenJSON)s)", 
                {"token":token, "userID":userID, "tokenJSON": generate_backup_codes(encrypt=True)}
            )
        except (MySQLErrors.IntegrityError):
            # If the 2FA tuple already exists, then update the token with a new token
            cur.execute(
                "UPDATE twofa_token SET token = %(token)s WHERE user_id = %(userID)s",
                {"token":token, "userID":userID}
            )
        connection.commit()

    elif (mode == "get_token"):
        userID = kwargs["userID"]
        cur.execute("SELECT token FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        matchedToken = cur.fetchone()
        if (matchedToken is None):
            raise No2FATokenError("No 2FA OTP found for this user!")

        # decrypt the encrypted secret token for 2fa
        token = symmetric_decrypt(ciphertext=matchedToken[0], keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID)
        return token

    elif (mode == "check_if_user_has_2fa"):
        userID = kwargs["userID"]
        cur.execute("SELECT token FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        matchedToken = cur.fetchone()
        if (matchedToken is None):
            return False

        return True if (matchedToken[0] is not None) else False

    elif (mode == "delete_token"):
        userID = kwargs["userID"]
        cur.execute("UPDATE twofa_token SET token = NULL WHERE user_id = %(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "get_backup_codes"):
        cur.execute(
            "SELECT backup_codes_json FROM twofa_token WHERE user_id = %(userID)s",
            {"userID": kwargs["userID"]}
        )
        matched = cur.fetchone()
        return json.loads(symmetric_decrypt(ciphertext=matched[0], keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID)) \
               if (matched is not None) else []

    elif (mode == "generate_codes"):
        userID = kwargs["userID"]

        # Overwrite the old backup codes if it exists
        backupCodes = generate_backup_codes(encrypt=False)
        encryptedBackupCodes = symmetric_encrypt(
            plaintext=json.dumps(backupCodes), 
            keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
        )
        cur.execute(
            "UPDATE twofa_token SET backup_codes_json = %(backupCodesJSON)s", 
            {"backupCodesJSON": encryptedBackupCodes}
        )
        connection.commit()
        return backupCodes

    elif (mode == "disable_2fa_with_backup_code"):
        cur.execute(
            "SELECT backup_codes_json FROM twofa_token WHERE user_id = %(userID)s",
            {"userID": kwargs["userID"]}
        )
        matched = cur.fetchone()
        if (matched is None):
            return False

        validFlag, idx = False, 0
        backupCodes = json.loads(symmetric_decrypt(ciphertext=matched[0], keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID))
        # try:
        #     validate(instance=backupCodes, schema=schema)
        # except:
        #     print("Error in Json schema")
        for idx, codeTuple in enumerate(backupCodes):
            if (codeTuple[0] == kwargs["backupCode"] and codeTuple[1] == "Active"):
                validFlag = True
                break

        if (validFlag):
            # Mark the backup code as used
            backupCodes[idx] = (kwargs["backupCode"], "Used")
            encryptedBackupCodesdArr = symmetric_encrypt(
                plaintext=json.dumps(backupCodes), keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
            )

            # Update the backup codes in the database
            cur.execute("UPDATE twofa_token SET backup_codes_json = %(backupCodesJSON)s WHERE user_id = %(userID)s", {"backupCodesJSON": encryptedBackupCodesdArr, "userID": kwargs["userID"]})

            # Update the token to null to disable 2FA
            cur.execute("UPDATE twofa_token SET token = NULL WHERE user_id = %(userID)s", {"userID": kwargs["userID"]})
            connection.commit()
            return True

        return False # Not valid

    else:
        raise ValueError("Invalid mode in the twofa_token_sql_operation function!")

def login_attempts_sql_operation(connection:MySQLConnection, mode:str=None, **kwargs) -> None:
    if (mode is None):
        raise ValueError("You must specify a mode in the login_attempts_sql_operation function!")

    cur = connection.cursor()

    if (mode == "add_attempt"):
        emailInput = kwargs["email"]
        cur.execute("SELECT id FROM user WHERE email = %(emailInput)s", {"emailInput":emailInput})
        userID = cur.fetchone()
        if (userID is None):
            raise EmailDoesNotExistError("Email does not exist!")

        userID = userID[0]
        cur.execute("SELECT attempts, reset_date FROM login_attempts WHERE user_id = %(userID)s", {"userID":userID})
        attempts = cur.fetchone()
        if (attempts is None):
            cur.execute("INSERT INTO login_attempts (user_id, attempts, reset_date) VALUES (%(userID)s, %(attempts)s, SGT_NOW() + INTERVAL %(intervalMins)s MINUTE)", {"userID":userID, "attempts":1, "intervalMins":CONSTANTS.LOCKED_ACCOUNT_DURATION})
        else:
            cur.execute("SELECT SGT_NOW()")
            now = cur.fetchone()[0]
            # comparing the reset datetime with the current datetime
            if (attempts[1] > now):
                # if not past the reset datetime
                currentAttempts = attempts[0]
            else:
                # if past the reset datetime, reset the attempts to 0
                currentAttempts = 0

            if (currentAttempts >= CONSTANTS.MAX_LOGIN_ATTEMPTS):
                # if reached max attempts per account
                raise AccountLockedError("User have exceeded the maximum number of password attempts!")

            cur.execute("UPDATE login_attempts SET attempts = %(currentAttempts)s, reset_date = SGT_NOW() + INTERVAL %(intervalMins)s MINUTE WHERE user_id = %(userID)s",{"currentAttempts":currentAttempts+1, "intervalMins":CONSTANTS.LOCKED_ACCOUNT_DURATION, "userID":userID})
        connection.commit()

    elif (mode == "reset_user_attempts_for_user"):
        userID = kwargs["userID"]
        cur.execute("DELETE FROM login_attempts WHERE user_id = %(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "reset_attempts_past_reset_date"):
        cur.execute("DELETE FROM login_attempts WHERE reset_date < SGT_NOW()")
        connection.commit()

    elif (mode == "reset_attempts_past_reset_date_for_user"):
        userID = kwargs["userID"]
        cur.execute("DELETE FROM login_attempts WHERE user_id = %(userID)s AND reset_date < SGT_NOW()", {"userID":userID})
        connection.commit()

        cur.execute("SELECT attempts FROM login_attempts WHERE user_id = %(userID)s", {"userID":userID})
        return True if (cur.fetchone() is None) else False

    else:
        raise ValueError("Invalid mode in the login_attempts_sql_operation function!")

def session_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[str, bool, None]:
    if (mode is None):
        raise ValueError("You must specify a mode in the session_sql_operation function!")

    cur = connection.cursor()

    # INET6_ATON and INET6_NTOA are functions in-built to mysql and are used to convert IPv4 and IPv6 addresses to and from a binary string
    # https://dev.mysql.com/doc/refman/8.0/en/miscellaneous-functions.html#function_inet6-ntoa
    if (mode == "create_session"):
        sessionID = kwargs["sessionID"]
        userID = kwargs["userID"]
        fingerprintHash = sha512(b".".join(
            [kwargs["userIP"].encode("utf-8"), kwargs["userAgent"].encode("utf-8")]
        )).hexdigest()

        cur.execute(
            "INSERT INTO session VALUES (%(sessionID)s, %(userID)s, SGT_NOW() + INTERVAL %(interval)s MINUTE, %(fingerprintHash)s)", 
            {"sessionID":sessionID, "userID":userID, "interval":CONSTANTS.SESSION_EXPIRY_INTERVALS, "fingerprintHash":fingerprintHash}
        )
        connection.commit()

    elif (mode == "delete_session"):
        sessionID = kwargs["sessionID"]
        cur.execute("DELETE FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        connection.commit()

    elif (mode == "check_if_valid"):
        sessionID = kwargs["sessionID"]
        userID = kwargs.get("userID")
        fingerprintHash = sha512(b".".join(
            [kwargs["userIP"].encode("utf-8"), kwargs["userAgent"].encode("utf-8")]
        )).hexdigest()

        # Get the session data from the database 
        # if the session ID exists, the fingerprint hash matches, and is not expired
        cur.execute(
            "SELECT * FROM session WHERE session_id = %(sessionID)s AND expiry_date > SGT_NOW() AND fingerprint_hash = %(fingerprintHash)s AND user_id = %(userID)s", 
            {"sessionID":sessionID, "fingerprintHash":fingerprintHash, "userID":userID}
        )
        if (cur.fetchone() is None):
            return False

        # Check if user is active or exists in the database
        cur.execute("SELECT status FROM user WHERE id = %(userID)s", {"userID":userID})
        matchedStatus = cur.fetchone()
        if (matchedStatus is None):
            return False
        elif (matchedStatus[0] != "Active"):
            cur.execute("DELETE FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
            connection.commit()
            return False

        # Session ID is valid, update the expiry date by adding an interval to the current time
        cur.execute(
            "UPDATE session SET expiry_date=SGT_NOW() + INTERVAL %(interval)s MINUTE WHERE session_id=%(sessionID)s", 
            {"interval":CONSTANTS.SESSION_EXPIRY_INTERVALS, "sessionID":sessionID}
        )
        connection.commit()
        return True

    elif (mode == "delete_expired_sessions"):
        cur.execute("DELETE FROM session WHERE expiry_date < SGT_NOW()")
        connection.commit()

    else:
        raise ValueError("Invalid mode in the session_sql_operation function!")

def user_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[str, tuple, bool, dict, None]:
    """
    Do CRUD operations on the user table

    insert keywords: email, username, password
    login keywords: email, password
    get_user_data keywords: userID
    get_user_cart keywords: userID
    add_to_cart keywords: userID, courseID
    remove_from_cart keywords: userID, courseID
    purchase_courses keywords: userID
    delete keywords: userID
    """
    if (mode is None):
        raise ValueError("You must specify a mode in the user_sql_operation function!")

    cur = connection.cursor()

    if (mode == "verify_userID_existence"):
        userID = kwargs["userID"]
        cur.execute("SELECT * FROM user WHERE id=%(userID)s", {"userID":userID})
        return bool(cur.fetchone())

    elif (mode == "check_if_active"):
        userID = kwargs["userID"]
        cur.execute("SELECT * FROM user WHERE id=%(userID)s AND status='Active'", {"userID":userID})
        return bool(cur.fetchone())

    elif (mode == "check_if_superadmin"):
        userID = kwargs["userID"]
        cur.execute("SELECT r.role_name FROM role AS r INNER JOIN user AS u ON r.role_id=u.role WHERE u.id=%(userID)s", {"userID":userID})
        return (cur.fetchone()[0] == "SuperAdmin")

    elif (mode == "fetch_user_id_from_email"):
        email = kwargs["email"]
        cur.execute("SELECT id FROM user WHERE email=%(email)s", {"email":email})
        matched = cur.fetchone()
        return matched[0] if (matched is not None) else None

    elif (mode == "email_verified"):
        userID = kwargs["userID"]
        getEmail = kwargs.get("email") or False
        cur.execute("SELECT email_verified, email FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        if (matched is None):
            return None
        return matched if (getEmail) else matched[0]

    elif (mode == "remove_unverified_users_more_than_30_days"):
        cur.execute("DELETE FROM user WHERE email_verified=0 AND date_joined < SGT_NOW() - INTERVAL 30 DAY")
        connection.commit()

    elif (mode == "update_email_to_verified"):
        userID = kwargs["userID"]
        cur.execute("UPDATE user SET email_verified = TRUE WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "re-encrypt_data_in_database"):
        # Used for re-encrypting all the encrypted data in the database at the last day of every month due to 30 days key rotations.
        current_app.config["MAINTENANCE_MODE"] = True
        cur.execute("SELECT u.id, u.password, tfa.token, tfa.backup_codes_json FROM user AS u LEFT OUTER JOIN twofa_token AS tfa ON u.id=tfa.user_id;")
        for row in cur.fetchall():
            userID = row[0]

            # Re-encrypt the password hash if the user has signed up 
            # via CourseFinity and not via Google OAuth2
            currentEncryptedPasswordHash = row[1]
            if (currentEncryptedPasswordHash is not None):
                try:
                    newEncryptedPasswordHash = symmetric_encrypt(
                        plaintext=symmetric_decrypt(
                            ciphertext=currentEncryptedPasswordHash, 
                            keyID=CONSTANTS.PEPPER_KEY_ID
                        ), 
                        keyID=CONSTANTS.PEPPER_KEY_ID
                    )
                except (DecryptionError) as e:
                    write_log_entry(
                        logMessage=f"Re-encryption of password hash has failed... Error: {e}",
                        severity="ALERT"
                    )
                    return
                cur.execute(
                    "UPDATE user SET password = %(password)s WHERE id=%(userID)s",
                    {"password":newEncryptedPasswordHash, "userID":userID}
                )
                connection.commit()

            # Re-encrypt the 2FA token if the user has set one
            oldEncryptedTwoFAToken = row[2]
            if (oldEncryptedTwoFAToken is not None):
                try:
                    newEncryptedToken = symmetric_encrypt(
                        plaintext=symmetric_decrypt(
                            ciphertext=oldEncryptedTwoFAToken,
                            keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                        ),
                        keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                    )
                except (DecryptionError):
                    write_log_entry(
                        logMessage="Re-encryption of 2FA token has failed...",
                        severity="ALERT"
                    )
                    return
                cur.execute(
                    "UPDATE twofa_token SET token = %(token)s WHERE user_id=%(userID)s",
                    {"token":newEncryptedToken, "userID":userID}
                )
                connection.commit()

            # Re-encrypt the backup codes if the user has set up 2FA
            oldEncryptedBackupCodes = row[3]
            if (oldEncryptedBackupCodes is not None):
                try:
                    newEncryptedBackupCodes = symmetric_encrypt(
                        plaintext=symmetric_decrypt(
                            ciphertext=oldEncryptedBackupCodes,
                            keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                        ),
                        keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                    )
                except (DecryptionError):
                    write_log_entry(
                        logMessage="Re-encryption of backup codes has failed...",
                        severity="ALERT"
                    )
                    return
                cur.execute(
                    "UPDATE twofa_token SET backup_codes_json = %(backupCodes)s WHERE user_id=%(userID)s",
                    {"backupCodes":newEncryptedBackupCodes, "userID":userID}
                )
                connection.commit()

        write_log_entry(
            logMessage=f"All sensitive user data have re-encrypted in the database at {datetime.now().astimezone(tz=ZoneInfo('Asia/Singapore'))}, please destroy the old symmetric keys used for the database as soon as possible!",
            severity="ALERT"
        )
        current_app.config["MAINTENANCE_MODE"] = False

    elif (mode == "signup"):
        emailInput = kwargs["email"]
        usernameInput = kwargs["username"]

        cur.execute("SELECT * FROM user WHERE email=%(emailInput)s", {"emailInput":emailInput})
        emailDupe = bool(cur.fetchone())

        cur.execute("SELECT * FROM user WHERE username=%(usernameInput)s", {"usernameInput":usernameInput})
        usernameDupes = bool(cur.fetchone())

        if (emailDupe or usernameDupes):
            return (emailDupe, usernameDupes)

        # add account info to the MySQL database
        # check if the generated uuid exists in the db
        userID = generate_id()
        while (user_sql_operation(connection=connection, mode="verify_userID_existence", userID=userID)):
            userID = generate_id()

        # encrypt the password hash, i.e. adding a pepper onto the hash
        passwordInput = symmetric_encrypt(plaintext=kwargs["password"], keyID=CONSTANTS.PEPPER_KEY_ID)

        cur.execute("CALL get_role_id(%(Student)s)", {"Student":"Student"})
        roleID = cur.fetchone()[0]

        cur.execute(
            "INSERT INTO user VALUES (%(userID)s, %(role)s, %(usernameInput)s, %(emailInput)s, FALSE, %(passwordInput)s, %(profile_image)s, SGT_NOW(), 'Active')",
            {"userID":userID, "role":roleID, "usernameInput":usernameInput, "emailInput":emailInput, "passwordInput":passwordInput, "profile_image":None}
        )
        connection.commit()

        user_ip_addresses_sql_operation(connection=connection, mode="add_ip_address", userID=userID, ipAddress=kwargs["ipAddress"])

        return userID

    elif (mode == "check_if_using_google_oauth2"):
        userID = kwargs["userID"]
        cur.execute("SELECT password FROM user WHERE id=%(userID)s", {"userID":userID})
        password = cur.fetchone()
        if (password is None):
            raise UserDoesNotExist("User does not exist!")

        # since those using Google OAuth2 will have a null password, we can check if it is null
        if (password[0] is None):
            return True
        else:
            return False

    elif (mode == "login_google_oauth2"):
        userID = kwargs["userID"]
        username = kwargs["username"]
        email = kwargs["email"]
        googleProfilePic = kwargs.get("googleProfilePic")

        # check if the email exists
        cur.execute("SELECT * FROM user WHERE email=%(email)s", {"email":email})
        matched = cur.fetchone()
        if (matched is None):
            # user does not exist, create new user with the given information
            cur.execute("CALL get_role_id('Student')")
            roleID = cur.fetchone()[0]

            cur.execute(
                "INSERT INTO user VALUES (%(userID)s, %(role)s, %(usernameInput)s, %(emailInput)s, TRUE, NULL, %(profile_image)s, SGT_NOW(), 'Active')",
                {"userID":userID, "role":roleID, "usernameInput":username, "emailInput":email, "profile_image":googleProfilePic}
            )
            connection.commit()
        else:
            # user exists, check if the user had used Google OAuth2 to sign up
            # by checking if the password is null
            if (matched[4] is not None):
                # user has not signed up using Google OAuth2,
                # return the generated userID from the database and the role name associated with the user
                cur.execute("CALL get_role_name(%(matched)s)", {"matched":matched[1]})
                roleName = cur.fetchone()[0]
                return (matched[0], roleName)

    elif (mode == "login"):
        emailInput = kwargs["email"]
        passwordInput = kwargs["password"]

        cur.execute("""SELECT u.id, u.password, u.username, u.role, u.email_verified, u.status 
            FROM user AS u INNER JOIN role AS r ON u.role = r.role_id
            WHERE u.email=%(emailInput)s AND r.role_name NOT IN ('Admin', 'SuperAdmin');""", {"emailInput":emailInput})
        matched = cur.fetchone()

        if (matched is None):
            raise EmailDoesNotExistError("Email does not exist!")

        username = matched[2]
        roleID = matched[3]
        encryptedPasswordHash = matched[1]
        userID = matched[0]
        emailVerified = matched[4]
        status = matched[5]

        if (status != "Active"):
            raise UserIsNotActiveError(f"User is not active but is currently \"{status}\"")

        if (encryptedPasswordHash is None):
            raise UserIsUsingOauth2Error("User is using Google OAuth2, please use Google OAuth2 to login!")

        cur.execute("SELECT attempts FROM login_attempts WHERE user_id= %(userID)s", {"userID":userID})
        loginAttempts = cur.fetchone()

        requestIpAddress = kwargs["ipAddress"]

        # Convert request IP address to hexadecimal format
        try:
            requestIPAddressHex = inet_aton(requestIpAddress).hex()
        except (OSError):
            requestIPAddressHex = inet_pton(AF_INET6, requestIpAddress).hex()

        ipAddressList = user_ip_addresses_sql_operation(connection=connection, mode="get_ip_addresses", userID=userID)

        # send an email to the authentic user if their account got locked
        if (loginAttempts and loginAttempts[0] > CONSTANTS.MAX_LOGIN_ATTEMPTS):
            resetAttempts = login_attempts_sql_operation(connection=connection, mode="reset_attempts_past_reset_date_for_user", userID=userID)

            # If the user has exceeded the maximum number of login attempts,
            # but the timeout is not up yet...
            if (not resetAttempts):
                send_unlock_locked_acc_email(email=emailInput, userID=userID)
                raise AccountLockedError("Account is locked!")

        # send verification email if the user has not verified their email
        if (not emailVerified):
            send_verification_email(email=emailInput, userID=userID, username=username)
            raise EmailNotVerifiedError("Email has not been verified, please verify your email!")

        newIpAddress = False
        decryptedPasswordHash = symmetric_decrypt(ciphertext=encryptedPasswordHash, keyID=CONSTANTS.PEPPER_KEY_ID)
        try:
            if (CONSTANTS.PH.verify(decryptedPasswordHash, passwordInput)):
                # check if the login request is from the same IP address as the one that made the request
                if (requestIPAddressHex not in ipAddressList):
                    newIpAddress = True

                # convert the role id to a readable format
                cur.execute("CALL get_role_name(%(roleID)s)", {"roleID":roleID})
                roleName = cur.fetchone()[0]

                return (userID, newIpAddress, username, roleName)
        except (VerifyMismatchError):
            raise IncorrectPwdError("Incorrect password!")
        except (VerificationError, InvalidHash) as e:
            write_log_entry(
                logMessage={
                    "User ID": userID,
                    "Purpose": "Login",
                    "Argon2 Error": str(e)
                },
                severity="ERROR"
            )
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "find_user_for_reset_password"):
        email = kwargs["email"]
        cur.execute("SELECT id, password FROM user WHERE email=%(email)s", {"email":email})
        matched = cur.fetchone()
        return matched

    elif (mode == "get_user_data"):
        userID = kwargs["userID"]
        cur.execute(
            "CALL get_user_data(%(userID)s, %(getCart)s)", 
            {"userID":userID, "getCart":kwargs.get("getCart", False)}
        )
        matched = cur.fetchone()
        return format_user_info(matched) if (matched is not None) else None

    elif (mode == "change_profile_picture"):
        userID = kwargs["userID"]

        # Delete old profile picture from Google Cloud Storage API
        cur.execute("SELECT profile_image FROM user WHERE id=%(userID)s", {"userID":userID})
        profileImage = cur.fetchone()[0]
        if (profileImage is not None):
            oldUrlToDelete = get_blob_name(url=profileImage)
            try:
                delete_blob(destinationURL=oldUrlToDelete)
            except (FileNotFoundError):
                pass

        # Change profile picture in the database
        profileImagePath = kwargs["profileImagePath"]
        cur.execute("UPDATE user SET profile_image=%(profile_image)s WHERE id=%(userID)s", {"profile_image":profileImagePath, "userID":userID})
        connection.commit()

    elif (mode == "delete_profile_picture"):
        userID = kwargs["userID"]

        # Delete old profile picture from Google Cloud Storage API
        cur.execute("SELECT profile_image FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        if (matched is not None and matched[0] is not None):
            oldUrlToDelete = get_blob_name(url=matched[0])
            try:
                delete_blob(destinationURL=oldUrlToDelete)
            except (FileNotFoundError):
                pass

        cur.execute("UPDATE user SET profile_image=%(profile_image)s WHERE id=%(userID)s", {"profile_image":None, "userID":userID})
        connection.commit()

    elif (mode == "change_username"):
        userID = kwargs["userID"]
        usernameInput = kwargs.get("username")
        cur.execute("SELECT * FROM user WHERE username=%(username)s", {"username":usernameInput})
        reusedUsername = bool(cur.fetchone())

        if (reusedUsername):
            raise ReusedUsernameError(f"The username {usernameInput} is already in use!")

        cur.execute("UPDATE user SET username=%(usernameInput)s WHERE id=%(userID)s", {"usernameInput": usernameInput, "userID": userID})
        connection.commit()

    elif (mode == "deactivate_user"):
        userID = kwargs["userID"]
        cur.execute("UPDATE user SET status='Inactive' WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "reactivate_user"):
        userID = kwargs["userID"]
        cur.execute("UPDATE user SET status='Active' WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "ban_user"):
        userID = kwargs["userID"]
        cur.execute("UPDATE user SET status='Banned' WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "unban_user"):
        userID = kwargs["userID"]
        cur.execute("UPDATE user SET status='Active' WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "admin_change_email"):
        userID = kwargs["userID"]
        emailInput = kwargs["email"]

        # check if the email is already in use
        cur.execute("SELECT id, password FROM user WHERE email=%(emailInput)s", {"emailInput":emailInput})
        reusedEmail = cur.fetchone()
        if (reusedEmail is not None):
            if (reusedEmail[0] == userID):
                raise SameAsOldEmailError(f"The email {emailInput} is the same as the old email!")
            else:
                raise EmailAlreadyInUseError(f"The email {emailInput} is already in use!")

        cur.execute("UPDATE user SET email=%(emailInput)s WHERE id=%(userID)s", {"emailInput": emailInput, "userID": userID})
        connection.commit()

    elif (mode == "change_email"):
        userID = kwargs["userID"]
        currentPasswordInput = kwargs.get("currentPassword")
        emailInput = kwargs["email"]

        # check if the email is already in use
        cur.execute("SELECT id, password FROM user WHERE email=%(emailInput)s", {"emailInput":emailInput})
        reusedEmail = cur.fetchone()
        if (reusedEmail is not None):
            if (reusedEmail[0] == userID):
                raise SameAsOldEmailError(f"The email {emailInput} is the same as the old email!")
            else:
                raise EmailAlreadyInUseError(f"The email {emailInput} is already in use!")

        cur.execute("SELECT password FROM user WHERE id=%(userID)s", {"userID":userID})
        currentPassword = symmetric_decrypt(ciphertext=cur.fetchone()[0], keyID=CONSTANTS.PEPPER_KEY_ID)
        try:
            if (CONSTANTS.PH.verify(currentPassword, currentPasswordInput)):
                cur.execute("UPDATE user SET email=%(emailInput)s, email_verified=FALSE WHERE id=%(userID)s", {"emailInput": emailInput, "userID":userID})
                connection.commit()
                send_verification_email(email=emailInput, userID=userID)
        except (VerifyMismatchError):
            raise IncorrectPwdError("Incorrect password!")
        except (VerificationError, InvalidHash) as e:
            write_log_entry(
                logMessage={
                    "User ID": userID,
                    "Purpose": "Change Email",
                    "Argon2 Error": str(e)
                },
                severity="ERROR"
            )
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "change_password"):
        userID = kwargs["userID"]
        oldPasswordInput = kwargs["oldPassword"] # to authenticate the changes
        passwordInput = kwargs["password"]

        cur.execute("SELECT password FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        currentPasswordHash = symmetric_decrypt(ciphertext=matched[0], keyID=CONSTANTS.PEPPER_KEY_ID)

        try:
            # check if the supplied old password matches the current password
            if (CONSTANTS.PH.verify(currentPasswordHash, oldPasswordInput)):
                if (len(passwordInput) < CONSTANTS.MIN_PASSWORD_LENGTH):
                    raise PwdTooShortError(f"The password must be at least {CONSTANTS.MIN_PASSWORD_LENGTH} characters long!")

                if (len(passwordInput) > CONSTANTS.MAX_PASSWORD_LENGTH):
                    raise PwdTooLongError(f"The password must be less than {CONSTANTS.MAX_PASSWORD_LENGTH} characters long!")

                passwordCompromised = pwd_has_been_pwned(passwordInput)
                if (isinstance(passwordCompromised, tuple) and not passwordCompromised[0]):
                    write_log_entry(
                        logMessage="haveibeenpwned's API is down, will fall back to strict password checking!",
                        severity="NOTICE"
                    )
                    raise haveibeenpwnedAPIDownError(f"The API is down and does not match all the password complexity requirements!")

                if (passwordCompromised):
                    raise PwdCompromisedError(f"The password has been compromised!")
                if (not pwd_is_strong(passwordInput)):
                    raise PwdTooWeakError("The password is too weak!")

                cur.execute(
                    "UPDATE user SET password=%(password)s WHERE id=%(userID)s",
                    {"password": symmetric_encrypt(plaintext=CONSTANTS.PH.hash(passwordInput), keyID=CONSTANTS.PEPPER_KEY_ID), "userID": userID}
                )
                connection.commit()
        except (VerifyMismatchError):
            raise IncorrectPwdError("Incorrect password!")
        except (VerificationError, InvalidHash) as e:
            write_log_entry(
                logMessage={
                    "User ID": userID,
                    "Purpose": "Change Password",
                    "Argon2 Error": str(e)
                },
                severity="ERROR"
            )
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "reset_password"):
        userID = kwargs["userID"]
        newPassword = kwargs["newPassword"]

        cur.execute(
            "UPDATE user SET password=%(password)s WHERE id=%(userID)s",
            {"password": symmetric_encrypt(plaintext=CONSTANTS.PH.hash(newPassword), keyID=CONSTANTS.PEPPER_KEY_ID), "userID": userID}
        )
        connection.commit()
        reset_password_sql_operation(connection=connection, mode="delete_token_by_user_id", userID=userID)

    elif (mode == "delete_user"):
        # Delete user from the database unlike deleting user's data from the database
        # Used for user who have not verified their email.
        userID = kwargs["userID"]
        cur.execute("DELETE FROM user WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "delete_user_data"):
        userID = kwargs["userID"]

        # Delete user's draft courses uploaded to vdocipher if any
        cur.execute("SELECT course_id FROM draft_course WHERE teacher_id=%(userID)s", {"userID":userID})
        courses = cur.fetchall()
        if (courses is not None or len(courses) > 0):
            courses = tuple([course[0] for course in courses])
            delete_video(videoIDs=courses)

        # Delete user's data from the database except the userID and username and uploaded courses if any
        cur.execute("CALL delete_user_data(%(userID)s)", {"userID":userID})
        connection.commit()

    elif (mode == "update_to_teacher"):
        userID = kwargs["userID"]

        cur.execute("CALL get_user_data(%(userID)s, 0)", {"userID":userID})
        currentRole = cur.fetchone()[0][1]

        isTeacher = False if (currentRole != "Teacher") else True
        if (not isTeacher):
            cur.execute("CALL get_role_id(%(Teacher)s)", {"Teacher":"Teacher"})
            teacherRoleID = cur.fetchone()[0]
            cur.execute("UPDATE user SET role=%(teacherRoleID)s WHERE id=%(userID)s", {"teacherRoleID": teacherRoleID, "userID":userID})
            connection.commit()
        else:
            raise IsAlreadyTeacherError("The user is already a teacher!")

    elif (mode == "paginate_users"):
        pageNum = kwargs["pageNum"]
        if (pageNum > 2147483647):
            pageNum = 2147483647

        userInput = kwargs.get("userInput")
        filterType = kwargs.get("filterType", "username") # To determine what the user input is (UID or username)

        paginationRole = kwargs["role"]
        if (paginationRole != "Admin"):
            # Students/Teachers (users) pagination
            if (userInput is None):
                cur.execute("CALL paginate_users(%(pageNum)s)", {"pageNum":pageNum})
            elif (filterType == "uid"):
                cur.execute("CALL paginate_users_by_uid(%(pageNum)s, %(userInput)s)", {"pageNum":pageNum, "userInput":userInput})
            elif (filterType == "email"):
                cur.execute("CALL paginate_users_by_email(%(pageNum)s, %(userInput)s)", {"pageNum":pageNum, "userInput":userInput})
            else:
                # Paginate by username by default in the HTML, 
                # but this is also a fallback if the user has tampered with the HTML value
                cur.execute("CALL paginate_users_by_username(%(pageNum)s, %(userInput)s)", {"pageNum":pageNum, "userInput":userInput})
        else: 
            # Admin users pagination
            if (userInput is None):
                cur.execute("CALL paginate_admins(%(pageNum)s)", {"pageNum":pageNum})
            elif (filterType == "uid"):
                cur.execute("CALL paginate_admins_by_uid(%(pageNum)s, %(userInput)s)", {"pageNum":pageNum, "userInput":userInput})
            elif (filterType == "email"):
                cur.execute("CALL paginate_admins_by_email(%(pageNum)s, %(userInput)s)", {"pageNum":pageNum, "userInput":userInput})
            else:
                # Paginate by username by default in the HTML, 
                # but this is also a fallback if the user has tampered with the HTML value
                cur.execute("CALL paginate_admins_by_username(%(pageNum)s, %(userInput)s)", {"pageNum":pageNum, "userInput":userInput})

        matched = cur.fetchall() or []
        maxPage = 1
        if (len(matched) > 0):
            maxPage = ceil(matched[0][-1] / 10)

        # To prevent infinite redirects
        if (maxPage <= 0):
            maxPage = 1

        if (pageNum > maxPage):
            return [], maxPage

        courseArr = []
        for data in matched:
            userInfo = format_user_info(data[1:])
            if (paginationRole != "Admin"):
                isInRecovery = recovery_token_sql_operation(
                    connection=connection, mode="check_if_recovering", userID=userInfo.uid
                )
                courseArr.append((userInfo, isInRecovery))
            else:
                courseArr.append(userInfo)

        return courseArr, maxPage

    # elif (mode == "get_user_purchases"):
    #     userID = kwargs["userID"]
    #     cur.execute("SELECT JSON_ARRAYAGG(course_id) FROM purchased_courses WHERE user_id=%(userID)s", {"userID":userID})
    #     return json.loads(cur.fetchone()[0])

    elif (mode == "paginate_user_purchases"):
        userID = kwargs["userID"]
        pageNum = kwargs["pageNum"]
        if (pageNum > 2147483647):
            pageNum = 2147483647

        cur.execute("CALL paginate_purchased_courses(%(userID)s, %(pageNum)s)", {"userID":userID, "pageNum":pageNum})
        matched = cur.fetchall() or []
        maxPage = 1
        if (len(matched) > 0):
            maxPage = ceil(matched[0][-1] / 10)

        # To prevent infinite redirects
        if (maxPage <= 0):
            maxPage = 1

        if (pageNum > maxPage):
            return [], maxPage

        courseArr = []
        for data in matched:
            data = data[1:]
            # Get the teacher's profile image from the first tuple
            teacherProfile = get_dicebear_image(data[2]) if (data[3] is None) \
                                                         else data[3]
            courseArr.append(CourseInfo(data, profilePic=teacherProfile, truncateData=True, getReadableCategory=True))

        return courseArr, maxPage

    elif mode == "get_user_cart":
        userID = kwargs["userID"]
        cur.execute("SELECT JSON_ARRAYAGG(course_id) FROM cart WHERE user_id=%(userID)s", {"userID":userID})
        return json.loads(cur.fetchone()[0])

    elif mode == "add_to_cart":
        userID = kwargs["userID"]
        courseID = kwargs["courseID"]

        cur.execute("SELECT * FROM cart WHERE user_id=%(userID)s AND course_id=%(courseID)s", {"userID":userID, "courseID":courseID})
        isInCart = True if (cur.fetchone() is not None) else False

        cur.execute("SELECT teacher_id, active FROM course WHERE course_id=%(courseID)s", {"courseID":courseID})
        matched = cur.fetchone()
        isSameTeacher = (matched[0] == userID)
        isActiveCourse = bool(matched[1])

        cur.execute(
            "SELECT * FROM purchased_courses WHERE course_id=%(courseID)s AND user_id=%(userID)s",
            {"courseID":courseID, "userID":userID}
        )
        isPurchased = True if (cur.fetchone() is not None) else False

        if (isActiveCourse and not isInCart and not isSameTeacher and not isPurchased):
            cur.execute("INSERT INTO cart (user_id, course_id) VALUES (%(userID)s, %(courseID)s)", {"userID":userID, "courseID":courseID})
            connection.commit()

    elif mode == "remove_from_cart":
        userID = kwargs["userID"]
        courseID = kwargs["courseID"]

        cur.execute(
            "DELETE FROM cart WHERE user_id=%(userID)s AND course_id=%(courseID)s", 
            {"userID":userID, "courseID":courseID}
        )
        connection.commit()

    elif mode == "purchase_courses":
        userID = kwargs["userID"]
        cartCourseIDs = kwargs["cartCourseIDs"]

        for courseID in cartCourseIDs:
            try:
                cur.execute(
                    "INSERT INTO purchased_courses (user_id, course_id) VALUES (%(userID)s, %(courseID)s)",
                    {"userID":userID, "courseID":courseID}
                )
                connection.commit()
            except (MySQLErrors.IntegrityError):
                # Catches if the for any duplicate key error
                write_log_entry(
                    logMessage=f"User {userID}, has purchased the course, {courseID}, but he/she had already purchased it",
                    severity="WARNING"
                )

        # Empty user's cart
        cur.execute("DELETE FROM cart WHERE user_id=%(userID)s", {"userID":userID})
        connection.commit()

    elif mode == "create_admin":
        username = kwargs["username"]
        email = kwargs["email"]
        profilePic = "https://storage.googleapis.com/coursefinity/user-profiles/default.png"
        adminID = generate_id()
        cur.execute("CALL get_role_id('Admin')")
        adminRoleID = cur.fetchone()[0]

        cur.execute(
            "INSERT INTO user (id, role, username, email, email_verified, profile_image, date_joined) VALUES (%(id)s, %(role)s, %(username)s, %(email)s, 1, %(profilePic)s, SGT_NOW())",
            {"id": adminID, "role": adminRoleID, "username": username, "email": email, "profilePic": profilePic}
        )
        connection.commit()

    else:
        raise ValueError("Invalid mode in the user_sql_operation function!")

def course_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs)  -> Union[list, tuple, bool, None]:
    """
    Do CRUD operations on the course table

    insert keywords: teacherID

    get_course_data keywords: courseID

    edit keywords:
    """
    if (not mode):
        raise ValueError("You must specify a mode in the course_sql_operation function!")

    cur = connection.cursor()

    if (mode == "insert"):
        courseID = kwargs["courseID"]
        teacherID = kwargs["teacherID"]
        courseName = kwargs["courseName"]
        courseDescription = kwargs["courseDescription"]
        courseImagePath = kwargs["courseImagePath"]
        coursePrice = kwargs["coursePrice"]
        courseCategory = kwargs["courseCategory"]
        videoPath = kwargs["videoPath"]

        cur.execute(
            "INSERT INTO course VALUES (%(courseID)s, %(teacherID)s, %(courseName)s, %(courseDescription)s, %(courseImagePath)s, %(coursePrice)s, %(courseCategory)s, SGT_NOW(), %(videoPath)s, 1)",
            {"courseID":courseID, "teacherID":teacherID, "courseName":courseName, "courseDescription":courseDescription, "courseImagePath":courseImagePath, "coursePrice":coursePrice, "courseCategory":courseCategory, "videoPath":videoPath}
        )
        connection.commit()
    
    elif (mode == "insert_draft"):
        courseID = kwargs["courseID"]
        teacherID = kwargs["teacherID"]
        videoPath = kwargs["videoPath"]
        print("INSERT INTO draft_course VALUES (%(courseID)s, %(teacherID)s, %(videoPath)s, SGT_NOW())" % 
            {"courseID": courseID, "teacherID": teacherID, "videoPath": videoPath})

        cur.execute(
            "INSERT INTO draft_course VALUES (%(courseID)s, %(teacherID)s, %(videoPath)s, SGT_NOW())", 
            {"courseID": courseID, "teacherID": teacherID, "videoPath": videoPath}
        )
        connection.commit()

    elif (mode == "check_if_course_owned_by_teacher"):
        courseID = kwargs["courseID"]
        teacherID = kwargs["teacherID"]
        cur.execute("SELECT * FROM course WHERE course_id=%(courseID)s AND teacher_id=%(teacherID)s", {"courseID":courseID, "teacherID":teacherID})
        return (cur.fetchone() is not None)

    elif (mode == "get_video_path"):
        courseID = kwargs["courseID"]
        cur.execute("SELECT video_path FROM course WHERE course_id=%(courseID)s", {"courseID":courseID})
        matched = cur.fetchone()
        return matched[0] if (matched is not None) else None

    elif (mode == "get_course_data"):
        courseID = kwargs["courseID"]
        print("Course ID:", courseID)
        cur.execute("CALL get_course_data(%(courseID)s)", {"courseID":courseID})
        matched = cur.fetchone()
        if (matched is None):
            return False
        teacherProfile = get_dicebear_image(matched[2]) if matched[3] is None else matched[3]
        return CourseInfo(tupleInfo=matched, profilePic=teacherProfile, truncateData=False, getReadableCategory=True)
    
    elif (mode == "get_draft_course_data"):
        courseID = kwargs["courseID"]
        print("Course ID:", courseID)
        cur.execute("SELECT * FROM draft_course WHERE course_id=%(courseID)s", {"courseID":courseID})
        matched = cur.fetchone()
        if (matched is None):
            return False

        return matched

    # Added just in case want to do updating
    elif (mode == "update_course_title"):
        courseID = kwargs["courseID"]
        courseTitle = kwargs["courseTitle"]
        cur.execute("UPDATE course SET course_name=%(courseTitle)s WHERE course_id=%(courseID)s", {"courseTitle":courseTitle, "courseID":courseID})
        connection.commit()

    elif (mode == "update_course_description"):
        courseID = kwargs["courseID"]
        courseDescription = kwargs["courseDescription"]
        cur.execute("UPDATE course SET course_description=%(courseDescription)s WHERE course_id=%(courseID)s", {"courseDescription":courseDescription, "courseID":courseID})
        connection.commit()

    elif (mode == "update_course_category"):
        courseID = kwargs["courseID"]
        courseCategory = kwargs["courseCategory"]
        cur.execute("UPDATE course SET course_category=%(courseCategory)s WHERE course_id=%(courseID)s", {"courseCategory":courseCategory, "courseID":courseID})
        connection.commit()

    elif (mode == "update_course_price"):
        courseID = kwargs["courseID"]
        coursePrice = kwargs.get("coursePrice")
        cur.execute("UPDATE course SET course_price=%(coursePrice)s WHERE course_id=%(courseID)s", {"coursePrice":coursePrice, "courseID":courseID})
        connection.commit()

    elif (mode == "update_course_thumbnail"):
        courseID = kwargs["courseID"]
        courseImagePath = kwargs["courseImagePath"]

        # Delete old thumbnail from Google Cloud Storage API
        cur.execute("SELECT course_image_path FROM course WHERE course_id=%(courseID)s", {"courseID":courseID})
        matched = cur.fetchone()
        if (matched is not None):
            oldUrlToDelete = get_blob_name(url=matched[0])
            try:
                delete_blob(destinationURL=oldUrlToDelete)
            except (FileNotFoundError):
                pass

        cur.execute("UPDATE course SET course_image_path=%(courseImagePath)s WHERE course_id=%(courseID)s", {"courseImagePath":courseImagePath, "courseID":courseID})
        connection.commit()

    elif (mode == "update_course_video"):
        courseID = kwargs["courseID"]
        videoPath = kwargs["videoPath"]
        cur.execute("UPDATE course SET video_path=%(videoPath)s WHERE course_id=%(courseID)s", {"videoPath":videoPath, "courseID":courseID})
        connection.commit()

    elif (mode == "delete_from_draft"):
        courseID = kwargs["courseID"]
        cur.execute("DELETE FROM draft_course WHERE course_id=%(courseID)s", {"courseID":courseID})
        connection.commit()

    elif (mode == "delete"):
        courseID = kwargs["courseID"]
        cur.execute("UPDATE course SET active=0 WHERE course_id=%(courseID)s", {"courseID":courseID})
        # cur.execute("DELETE FROM course WHERE course_id=%(courseID)s", {"courseID":courseID})
        connection.commit()

    elif (mode == "get_all_courses_by_teacher"):
        teacherID = kwargs["teacherID"]
        if (len(teacherID) > 32):
            teacherID = teacherID[:32]

        pageNum = kwargs["pageNum"]
        getTeacherName = kwargs.get("getTeacherName", False)
        if (pageNum > 2147483647):
            pageNum = 2147483647

        cur.execute("CALL paginate_teacher_courses(%(teacherID)s, %(pageNum)s)", {"teacherID":teacherID, "pageNum":pageNum})
        resultsList = cur.fetchall()
        if (resultsList is None or len(resultsList) < 1):
            return ([], 1, "") if (getTeacherName) else ([], 1)

        maxPage = ceil(resultsList[0][-1] / 10)
        if (maxPage <= 0):
            maxPage = 1

        teacherName = ""
        if (getTeacherName):
            cur.execute("SELECT username FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
            teacherName = cur.fetchone()
            if (teacherName is None):
                return ([], 1, "")
            teacherName = teacherName[0]

        # Get the teacher's profile image from the first tuple
        teacherProfile = get_dicebear_image(resultsList[0][3]) if (resultsList[0][4] is None) \
                                                               else resultsList[0][4]

        courseList = []
        loggedInUserID = kwargs.get("userID")
        for tupleInfo in resultsList:
            foundResultsTuple = tupleInfo[1:]

            purchased = isInCart = False
            if (loggedInUserID is not None):
                cur.execute(
                    "SELECT * FROM purchased_courses WHERE course_id=%(courseID)s AND user_id=%(userID)s",
                    {"courseID":foundResultsTuple[0], "userID":loggedInUserID}
                )
                purchased = True if (cur.fetchone() is not None) else False
                cur.execute(
                    "SELECT * FROM cart WHERE course_id=%(courseID)s AND user_id=%(userID)s",
                    {"courseID":foundResultsTuple[0], "userID":loggedInUserID}
                )
                isInCart = True if (cur.fetchone() is not None) else False

            courseList.append(
                (CourseInfo(foundResultsTuple, profilePic=teacherProfile, truncateData=True),
                {"purchased":purchased, "isInCart":isInCart})
            )

        return (courseList, maxPage, teacherName) if (getTeacherName) else (courseList, maxPage)

    elif (mode == "get_all_draft_courses"):
        teacherID = kwargs["teacherID"]
        pageNum = kwargs["pageNum"]
        if (pageNum > 2147483647):
            pageNum = 2147483647

        cur.execute("CALL paginate_draft_courses(%(teacherID)s, %(pageNum)s)", {"teacherID":teacherID, "pageNum":pageNum})
        resultsList = cur.fetchall()
        if (resultsList is None or len(resultsList) < 1):
            return ([], 1)

        maxPage = ceil(resultsList[0][-1] / 10)
        if (maxPage <= 0):
            maxPage = 1

        teacherProfile = get_dicebear_image(resultsList[0][3]) if (resultsList[0][4] is None) \
                                                               else resultsList[0][4]

        courseList = []
        cur.execute("SELECT SGT_NOW()")
        currentDay = cur.fetchone()[0]
        for tupleInfo in resultsList:
            foundResultsTuple = tupleInfo[1:]
            if ((currentDay - foundResultsTuple[4]).days > 1):
                cur.execute("DELETE FROM draft_course WHERE course_id=%(courseID)s", {"courseID":foundResultsTuple[0]})
                delete_video(foundResultsTuple[-2])
                connection.commit()
            else:
                print(foundResultsTuple)
                courseList.append(
                    CourseInfo(foundResultsTuple, profilePic=teacherProfile, truncateData=True, draftStatus=True)
                )

        return (courseList, maxPage)

    elif (mode == "get_3_latest_courses" or mode == "get_3_highly_rated_courses"):
        teacherID = kwargs.get("teacherID")

        # TODO: Fix the query below 
        if (mode == "get_3_latest_courses"):
            # get the latest 3 courses
            if (teacherID is None):
                cur.execute("""
                    SELECT 
                    c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created,
                    ROUND(SUM(r.course_rating) / COUNT(*), 0) AS avg_rating, c.video_path
                    FROM course AS c
                    LEFT OUTER JOIN review AS r
                    ON c.course_id = r.course_id
                    INNER JOIN user AS u
                    ON c.teacher_id=u.id
                    WHERE c.active=1
                    GROUP BY c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created
                    ORDER BY c.date_created DESC LIMIT 3;
                """)
            else:
                cur.execute("""
                    SELECT 
                    c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created,
                    ROUND(SUM(r.course_rating) / COUNT(*), 0) AS avg_rating, c.video_path
                    FROM course AS c
                    LEFT OUTER JOIN review AS r
                    ON c.course_id = r.course_id
                    INNER JOIN user AS u
                    ON c.teacher_id=u.id
                    WHERE c.teacher_id=%(teacherID)s AND c.active=1
                    GROUP BY c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created
                    ORDER BY c.date_created DESC LIMIT 3;
                """, {"teacherID":teacherID})
        else:
            # get top 3 highly rated courses
            if (teacherID is None):
                cur.execute("""
                    SELECT 
                    c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created,
                    ROUND(SUM(r.course_rating) / COUNT(*), 0) AS avg_rating, c.video_path
                    FROM course AS c
                    LEFT OUTER JOIN review AS r
                    ON c.course_id = r.course_id
                    INNER JOIN user AS u
                    ON c.teacher_id=u.id
                    WHERE c.active=1
                    GROUP BY c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created
                    ORDER BY avg_rating DESC LIMIT 3;
                """)
            else:
                cur.execute("""
                    SELECT 
                    c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created,
                    ROUND(SUM(r.course_rating) / COUNT(*), 0) AS avg_rating, c.video_path
                    FROM course AS c
                    LEFT OUTER JOIN review AS r
                    ON c.course_id = r.course_id
                    INNER JOIN user AS u
                    ON c.teacher_id=u.id
                    WHERE c.teacher_id=%(teacherID)s AND c.active=1
                    GROUP BY c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created
                    ORDER BY avg_rating DESC LIMIT 3;
                """, {"teacherID":teacherID})

        loggedInUserID = kwargs.get("userID")
        matchedList = cur.fetchall()
        if (not matchedList):
            return []
        else:
            courseInfoList = []
            # get the teacher name for each course
            if (not teacherID):
                teacherIDList = [teacherID[1] for teacherID in matchedList]
                for i, teacherID in enumerate(teacherIDList):
                    cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
                    res = cur.fetchone()
                    teacherProfile = get_dicebear_image(res[0]) if (res[1] is None) \
                                                                        else res[1]

                    purchased = isInCart = False
                    if (loggedInUserID is not None):
                        cur.execute(
                            "SELECT * FROM purchased_courses WHERE course_id=%(courseID)s AND user_id=%(userID)s",
                            {"courseID":matchedList[i][0], "userID":loggedInUserID}
                        )
                        purchased = True if (cur.fetchone() is not None) else False
                        cur.execute(
                            "SELECT * FROM cart WHERE course_id=%(courseID)s AND user_id=%(userID)s",
                            {"courseID":matchedList[i][0], "userID":loggedInUserID}
                        )
                        isInCart = True if (cur.fetchone() is not None) else False

                    courseInfoList.append(
                        (CourseInfo(matchedList[i], profilePic=teacherProfile, truncateData=True),
                        {"purchased":purchased, "isInCart":isInCart})
                    )
                return courseInfoList
            else:
                cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
                res = cur.fetchone()
                teacherProfile = get_dicebear_image(res[0]) if (res[1] is None) \
                                                                    else res[1]
                for tupleInfo in matchedList:
                    purchased = isInCart = False
                    if (loggedInUserID is not None):
                        cur.execute(
                            "SELECT * FROM purchased_courses WHERE course_id=%(courseID)s AND user_id=%(userID)s",
                            {"courseID":tupleInfo[0], "userID":loggedInUserID}
                        )
                        purchased = True if (cur.fetchone() is not None) else False
                        cur.execute(
                            "SELECT * FROM cart WHERE course_id=%(courseID)s AND user_id=%(userID)s",
                            {"courseID":tupleInfo[0], "userID":loggedInUserID}
                        )
                        isInCart = True if (cur.fetchone() is not None) else False

                    courseInfoList.append(
                        (CourseInfo(tupleInfo, profilePic=teacherProfile, truncateData=True),
                        {"purchased":purchased, "isInCart":isInCart})
                    )

                if (kwargs.get("getTeacherUsername")):
                    return (courseInfoList, res[0])

                return courseInfoList

    elif (mode == "search") or (mode == "explore"):
        courseTag = kwargs.get("courseCategory")
        searchInput = kwargs.get("searchInput")
        pageNum = kwargs.get("pageNum")
        if (pageNum > 2147483647):
            pageNum = 2147483647

        resultsList = []
        if (mode == "search"):
            cur.execute("CALL search_course_paginate(%(pageNum)s, %(searchInput)s)", {"pageNum":pageNum,"searchInput":searchInput})
        else:
            cur.execute("CALL explore_course_paginate(%(pageNum)s, %(courseTag)s)", {"pageNum":pageNum,"courseTag":courseTag})

        foundResults = cur.fetchall()
        if (len(foundResults) == 0):
            return []

        maxPage = ceil(foundResults[0][-1] / 10)
        teacherIDList = [teacherID[2] for teacherID in foundResults]
        for i, teacherID in enumerate(teacherIDList):
            cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
            res = cur.fetchone()
            teacherProfile = get_dicebear_image(res[0]) if (res[1] is None) \
                                                                else res[1]
            foundResultsTuple = foundResults[i][1:]
            resultsList.append(CourseInfo(foundResultsTuple, profilePic=teacherProfile, truncateData=True))

        return (resultsList, maxPage)

    else:
        raise ValueError("Invalid mode in the course_sql_operation function!")

def review_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the review table

    revieve_user_review keywords: userID, courseID,
    insert keywords: userID, courseID, courseRating, CourseReview
    retrieve_all keywords: courseID
    """
    if mode is None:
        raise ValueError("You must specify a mode in the review_sql_operation function!")

    cur = connection.cursor()
    courseID = kwargs["courseID"]

    if mode == "retrieve_user_review":
        userID = kwargs["userID"]
        cur.execute("SELECT course_rating FROM review WHERE user_id = %(userID)s AND course_id = %(courseID)s", {"userID":userID, "courseID":courseID})
        review_list = cur.fetchall()
        return review_list

    elif mode == "add_review":
        userID = kwargs["userID"]
        courseID = kwargs["courseID"]
        courseRating = kwargs["courseRating"]
        courseReview = kwargs["courseReview"]
        print(userID, courseID, courseRating, courseReview)
        cur.execute("INSERT INTO review (user_id, course_id, course_rating, course_review, review_date) VALUES (%(userID)s, %(courseID)s, %(courseRating)s, %(courseReview)s, SGT_NOW())", {"userID":userID, "courseID":courseID, "courseRating":courseRating, "courseReview":courseReview})
        connection.commit()

    elif mode == "retrieve_all":
        cur.execute("SELECT r.user_id, r.course_id, r.course_rating, r.course_review, r.review_date, u.username FROM review r INNER JOIN user u ON r.user_id = u.id WHERE r.course_id = %(courseID)s", {"courseID":courseID})
        review_list = cur.fetchall()
        return review_list if (review_list is not None) else []

    elif (mode == "check_if_user_reviewed"):
        cur.execute("SELECT * FROM review WHERE user_id = %(userID)s AND course_id = %(courseID)s", {"userID":kwargs["userID"], "courseID":courseID})
        return True if (cur.fetchone() is not None) else False

    elif (mode == "get_user_review"):
        userID = kwargs["userID"]

        cur.execute("SELECT * FROM review WHERE user_id = %(userID)s AND course_id = %(courseID)s", {"userID":userID, "courseID":courseID})
        matchedReview = cur.fetchone()
        if (matchedReview is None):
            return (False, None)

        print("Review:", matchedReview)
        return (True, ReviewInfo(matchedReview))

    elif (mode == "get_3_latest_user_review"):
        cur.execute("SELECT r.user_id, r.course_id, r.course_rating, r.course_review, r.review_date, u.username FROM review r INNER JOIN user u ON r.user_id = u.id WHERE r.course_id = %(courseID)s ORDER BY r.review_date DESC LIMIT 3", {"courseID":courseID})
        matchedReview = cur.fetchall()
        if (matchedReview is None):
            return []

        reviewArr = []
        for tupleData in matchedReview:
            reviewUserID = tupleData[0]
            reviewInfo = get_image_path(reviewUserID, returnUserInfo=True)
            imageSrcPath = reviewInfo.profileImage
            reviewArr.append(Reviews(tupleData=tupleData, courseID=courseID, profileImage=imageSrcPath))
        return reviewArr

    elif (mode == "paginate_reviews"):
        pageNum = kwargs["pageNum"]
        if (pageNum > 2147483647):
            pageNum = 2147483647

        cur.execute("CALL paginate_review_by_course(%(pageNum)s, %(courseID)s)", {"courseID":courseID, "pageNum":pageNum})
        matchedReview = cur.fetchall()
        if (matchedReview is None or len(matchedReview) < 1):
            return ([], 1)

        maxPage = 1
        if (len(matchedReview) > 0):
            maxPage = ceil(matchedReview[0][-1] / 10)

        # To prevent infinite redirects
        if (maxPage <= 0):
            maxPage = 1

        reviewArr = []
        for tupleData in matchedReview:
            tupleData = tupleData[1:]
            reviewUserID = tupleData[0]
            reviewInfo = get_image_path(reviewUserID, returnUserInfo=True)
            imageSrcPath = reviewInfo.profileImage
            reviewArr.append(Reviews(tupleData=tupleData, courseID=courseID, profileImage=imageSrcPath))
        return (reviewArr, maxPage)

    else:
        raise ValueError("Invalid mode in the review_sql_operation function!")

def role_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the review table
    
    """
    if mode is None:
        raise ValueError("You must specify a mode in the role_sql_operation function!")

    cur = connection.cursor()

    if mode == "retrieve_all":
        cur.execute("SELECT * FROM role ORDER BY role_id")
        role_list = cur.fetchall()
        return role_list if (role_list is not None) else []

    elif mode == "retrieve_admin":
        cur.execute("SELECT * FROM role WHERE role_name = 'Admin'")
        role_list = cur.fetchall()
        return role_list if (role_list is not None) else []

    elif mode == "retrieve_role":
        roleName = kwargs["roleName"].title()
        cur.execute("SELECT * FROM role WHERE role_name = '%(roleName)s'", {"roleName":roleName})
        role_list = cur.fetchone()
        return role_list if (role_list is not None) else []

    elif mode == "update_role": #updates the role of a group
        roleName = kwargs["roleName"].title()
        guestBP = kwargs["guestBP"]
        generalBP = kwargs["generalBP"]
        adminBP = kwargs["adminBP"]
        loggedInBP = kwargs["loggedInBP"]
        teacherBP= kwargs["teacherBP"]
        userBP= kwargs["userBP"]
        cur.execute(
            "UPDATE role SET guest_bp = %(guestBP)s, general_bp = %(generalBP)s, admin_bp = %(adminBP)s, logged_in_bp = %(loggedInBP)s, teacher_bp = %(teacherBP)s, user_bp = %(userBP)s WHERE role_name = %(roleName)s",
            {"roleName":roleName, "guestBP":guestBP, "generalBP":generalBP, "adminBP":adminBP, "loggedInBP":loggedInBP, "teacherBP":teacherBP, "userBP":userBP}
        )
        connection.commit()

    else:
        raise ValueError("Invalid mode in the role_sql_operation function!")