"""
This python file contains all the functions that touches on the MySQL database.
"""
# import python standard libraries
import json
from typing import Union, Optional
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from hashlib import sha512
from secrets import token_hex

# import Flask web application configs
from flask import url_for, current_app

# import third party libraries
from argon2.exceptions import VerifyMismatchError
import pymysql.err as MySQLErrors
from pymysql.connections import Connection as MySQLConnection

# import local python files
from python_files.classes.Course import Course, CourseInfo
from python_files.classes.Errors import *
from .NormalFunctions import JWTExpiryProperties, generate_id, pwd_has_been_pwned, pwd_is_strong, \
                             symmetric_encrypt, symmetric_decrypt, EC_sign, get_dicebear_image, \
                             send_email, write_log_entry, get_mysql_connection
from python_files.classes.Constants import CONSTANTS

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
    sessionID = token_hex(32) # Generate a 32 bytes session ID  using the secrets module from Python standard library
                              # as recommended by OWASP to ensure higher entropy: 
                              # https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation

    sql_operation(table="session", mode="create_session", sessionID=sessionID, userID=userID, userIP=userIP, userAgent=userAgent)
    return sessionID

def generate_limited_usage_jwt_token(payload:Union[str, list, dict]="", expiryInfo:Optional[JWTExpiryProperties]=None, limit:Optional[int]=None) -> str:
    """
    Generate a limited usage token and add it to the MySQL database.

    Args:
    - payload (Union[str, list, dict]): The payload of the token.
    - expiryInfo (JWTExpiryProperties, Optional): The expiry information of the token.
    - limit (int, Optional): The usage limit of the token.
    """
    if (expiryInfo is None and limit is None):
        raise ValueError("Either expiryInfo OR limit must be specified.")

    if (expiryInfo is not None and not isinstance(expiryInfo, JWTExpiryProperties)):
        raise ValueError("Defined expiry information must be a JWTExpiryProperties object.")\

    expiryInfoToStore = None
    if (expiryInfo is not None):
        expiryInfoToStore = expiryInfo.expiryDate.replace(microsecond=0, tzinfo=None)

    tokenID = token_hex(32) # Generate a 32 bytes token ID  using the secrets module from Python standard library
                            # as recommended by OWASP to ensure higher entropy: 
                            # https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation
    token = EC_sign(payload=payload, b64EncodeData=True, expiry=expiryInfo, tokenID=tokenID)
    sql_operation(
        table="limited_use_jwt", mode="add_jwt", tokenID=tokenID,
        expiryDate=expiryInfoToStore, limit=limit
    )
    return token

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
    htmlBody = [
        f"Welcome to CourseFinity!",
        f"Please click the link below to verify your email address:<br>{url_for('guestBP.verifyEmail', token=token, _external=True)}"
    ]
    send_email(to=email, subject="Please verify your email!", body="<br><br>".join(htmlBody), name=username)

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
    htmlBody = [
        "Your account has been locked due to too many failed login attempts.",
        f"Please click the link below to unlock your account:<br>{url_for('guestBP.unlockAccount', token=token, _external=True)}",
        "Note that this link will expire in 30 minutes as the account locked timeout will last for 30 minutes."
    ]
    send_email(to=email, subject="Unlock your account!", body="<br><br>".join(htmlBody))

def get_image_path(userID:str, returnUserInfo:bool=False) -> Union[str, tuple]:
    """
    Returns the image path for the user.

    If the user does not have a profile image uploaded, it will return a dicebear url.
    Else, it will return the relative path of the user's profile image.

    If returnUserInfo is True, it will return a tuple of the user's record.

    Args:
    - userID: The user's ID
    - returnUserInfo: If True, it will return a tuple of the user's record.

    Returns:
    - The image path (str) only if returnUserInfo is False
    - The image path (str) and the user's record (tuple) if returnUserInfo is True
    """
    userInfo = sql_operation(table="user", mode="get_user_data", userID=userID)

    # Since the admin user will not have an upload profile image feature,
    # return an empty string for the image profile src link if the user is the admin user.
    if (userInfo[1] == "Admin"):
        adminProfileImagePath = url_for("static", filename="images/user/default.png")
        return adminProfileImagePath if (not returnUserInfo) else (adminProfileImagePath, userInfo)

    imageSrcPath = userInfo[6]
    if (imageSrcPath is None):
        imageSrcPath = get_dicebear_image(userInfo[2])
    return imageSrcPath if (not returnUserInfo) else (imageSrcPath, userInfo)

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
        con = get_mysql_connection(debug=CONSTANTS.DEBUG_MODE)
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
            elif (table == "limited_use_jwt"):
                returnValue = limited_use_jwt_sql_operation(connection=con, mode=mode, **kwargs)
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

    return returnValue

def limited_use_jwt_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[bool, None]:
    """
    Connects to the database and returns the connection object

    Args:
    - connection: The connection to the database
    - mode: The mode to use ("insert", "edit", "login", etc.)
    - kwargs: The keywords to pass into the respective sql operation functions

    Returns the returned value from the SQL operation.
    """
    if (mode == "add_jwt"):
        tokenID = kwargs["tokenID"]
        expiryDate = kwargs.get("expiryDate")
        limit = kwargs.get("limit")
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO limited_use_jwt (id, expiry_date, token_limit) VALUES (%(tokenID)s, %(expiryDate)s, %(tokenLimit)s)",
            {"tokenID": tokenID, "expiryDate": expiryDate, "tokenLimit": limit}
        )
        connection.commit()
    elif (mode == "decrement_limit_after_use"):
        tokenID = kwargs["tokenID"]
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE limited_use_jwt SET token_limit = token_limit - 1 WHERE id = %(tokenID)s AND token_limit IS NOT NULL AND token_limit > 0",
            {"tokenID": tokenID}
        )
        connection.commit()
        cursor.execute(
            "DELETE FROM limited_use_jwt WHERE id = %(tokenID)s AND token_limit IS NOT NULL AND token_limit <= 0",
            {"tokenID": tokenID}
        )
        connection.commit()
    elif (mode == "jwt_is_valid"):
        tokenID = kwargs["tokenID"]
        print("token", tokenID)
        cursor = connection.cursor()
        cursor.execute(
            "SELECT token_limit FROM limited_use_jwt WHERE id = %(tokenID)s",
            {"tokenID": tokenID}
        )
        matched = cursor.fetchone()
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
        cursor = connection.cursor()
        cursor.execute("DELETE FROM limited_use_jwt WHERE expiry_date < SGT_NOW() OR token_limit <= 0")
        connection.commit()
    else:
        raise ValueError("Invalid mode")

def user_ip_addresses_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[list, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the user_ip_addresses_sql_operation function!")

    cur = connection.cursor()

    # INET6_ATON and INET6_NTOA are functions in-built to mysql and are used to convert IPv4 and IPv6 addresses to and from a binary string
    # https://dev.mysql.com/doc/refman/8.0/en/miscellaneous-functions.html#function_inet6-ntoa
    if (mode == "add_ip_address"):
        userID = kwargs["userID"]
        ipAddress = kwargs["ipAddress"]
        ipDetails = kwargs.get("ipDetails") or json.dumps(CONSTANTS.IPINFO_HANDLER.getDetails(ipAddress).all)

        cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address, ip_address_details, last_accessed) VALUES (%(userID)s, INET6_ATON(%(ipAddress)s), %(ipDetails)s, SGT_NOW())", {"userID":userID, "ipAddress":ipAddress, "ipDetails":ipDetails})
        connection.commit()

    elif (mode == "get_ip_addresses"):
        userID = kwargs["userID"]

        cur.execute("SELECT INET6_NTOA(ip_address) FROM user_ip_addresses WHERE user_id = %(userID)s", {"userID":userID})
        returnValue = cur.fetchall()
        ipAddressList = [ipAddress[0] for ipAddress in returnValue]
        return ipAddressList

    elif (mode == "add_ip_address_only_if_unique"):
        userID = kwargs["userID"]
        ipAddress = kwargs.get("ipAddress")
        ipDetails = kwargs.get("ipDetails") or json.dumps(CONSTANTS.IPINFO_HANDLER.getDetails(ipAddress).all)

        cur.execute("SELECT * FROM user_ip_addresses WHERE user_id = %(userID)s AND ip_address = INET6_ATON(%(ipAddress)s)", {"userID":userID, "ipAddress":ipAddress})
        if (cur.fetchone() is None):
            cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address, ip_address_details, last_accessed) VALUES (%(userID)s, INET6_ATON(%(ipAddress)s), %(ipDetails)s, SGT_NOW())", {"userID":userID, "ipAddress":ipAddress, "ipDetails":ipDetails})
            connection.commit()

    elif (mode == "remove_last_accessed_more_than_10_days"):
        cur.execute("DELETE FROM user_ip_addresses WHERE DATEDIFF(SGT_NOW(), last_accessed) > 10")
        connection.commit()

    else:
        connection.close()
        raise ValueError("Invalid mode in the user_ip_addresses_sql_operation function!")

def twofa_token_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[bool, str, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the twofa_token_sql_operation function!")

    """
    Set buffered = True

    The reason is that without a buffered cursor, the results are "lazily" loaded, meaning that "fetchone" actually only fetches one row from the full result set of the query. When you will use the same cursor again, it will complain that you still have n-1 results (where n is the result set amount) waiting to be fetched. However, when you use a buffered cursor the connector fetches ALL rows behind the scenes and you just take one from the connector so the mysql db won't complain.
    """
    cur = connection.cursor()

    if (mode == "add_token"):
        token = kwargs["token"]
        userID = kwargs["userID"]
        token = symmetric_encrypt(plaintext=token, keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID)

        cur.execute("INSERT INTO twofa_token (token, user_id) VALUES (%(token)s, %(userID)s)", {"token":token, "userID":userID})
        connection.commit()

    elif (mode == "get_token"):
        userID = kwargs["userID"]
        cur.execute("SELECT token FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        matchedToken = cur.fetchone()
        if (matchedToken is None):
            connection.close()
            raise No2FATokenError("No 2FA OTP found for this user!")

        # decrypt the encrypted secret token for 2fa
        token = symmetric_decrypt(ciphertext=matchedToken[0], keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID)
        return token

    elif (mode == "check_if_user_has_2fa"):
        userID = kwargs["userID"]
        cur.execute("SELECT token FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        matchedToken = cur.fetchone()
        return True if (matchedToken is not None) else False

    elif (mode == "delete_token"):
        userID = kwargs["userID"]
        cur.execute("DELETE FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        connection.commit()

    else:
        connection.close()
        raise ValueError("Invalid mode in the twofa_token_sql_operation function!")

def login_attempts_sql_operation(connection:MySQLConnection, mode:str=None, **kwargs) -> None:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the login_attempts_sql_operation function!")

    cur = connection.cursor()

    if (mode == "add_attempt"):
        emailInput = kwargs["email"]
        cur.execute("SELECT id FROM user WHERE email = %(emailInput)s", {"emailInput":emailInput})
        userID = cur.fetchone()
        if (userID is None):
            connection.close()
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

            if (currentAttempts > CONSTANTS.MAX_LOGIN_ATTEMPTS):
                # if reached max attempts per account
                connection.close()
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
        connection.close()
        raise ValueError("Invalid mode in the login_attempts_sql_operation function!")

def session_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[str, bool, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the session_sql_operation function!")

    cur = connection.cursor()

    # INET6_ATON and INET6_NTOA are functions in-built to mysql and are used to convert IPv4 and IPv6 addresses to and from a binary string
    # https://dev.mysql.com/doc/refman/8.0/en/miscellaneous-functions.html#function_inet6-ntoa
    if (mode == "create_session"):
        sessionID = ["sessionID"]
        userID = kwargs["userID"]
        fingerprintHash = sha512(kwargs["userIP"].encode("utf-8") + b"." + kwargs["userAgent"].encode("utf-8")).hexdigest()

        cur.execute("INSERT INTO session VALUES (%(sessionID)s, %(userID)s, SGT_NOW() + INTERVAL %(intervalMins)s MINUTE, %(fingerprintHash)s)", {"sessionID":sessionID, "userID":userID, "intervalMins":CONSTANTS.SESSION_EXPIRY_INTERVALS, "fingerprintHash":fingerprintHash})
        connection.commit()

    elif (mode == "get_user_id"):
        sessionID = ["sessionID"]
        cur.execute("SELECT user_id FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        userID = cur.fetchone()[0]
        return userID

    elif (mode == "get_session"):
        sessionID = ["sessionID"]
        cur.execute("SELECT * FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        returnValue = cur.fetchone()
        return returnValue

    elif (mode == "delete_session"):
        sessionID = ["sessionID"]
        cur.execute("DELETE FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        connection.commit()

    elif (mode == "update_session"):
        sessionID = ["sessionID"]
        cur.execute("UPDATE session SET expiry_date = SGT_NOW() + INTERVAL %(intervalMins)s MINUTE WHERE session_id = %(sessionID)s", {"intervalMins": CONSTANTS.SESSION_EXPIRY_INTERVALS, "sessionID": sessionID})
        connection.commit()

    elif (mode == "check_if_valid"):
        sessionID = ["sessionID"]
        cur.execute("SELECT user_id, expiry_date, fingerprint_hash FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        result = cur.fetchone()
        storedUserID = result[0]
        expiryDate = result[1]
        storedFingerprintHash = result[2]
        cur.execute("SELECT SGT_NOW()")
        if (expiryDate >= cur.fetchone()[0]):
            # not expired, check if the userID matches the sessionID
            # and if the fingerprint hash matches the storedFingerprintHash
            userID = kwargs.get("userID")
            fingerprintHash = sha512(kwargs["userIP"].encode("utf-8") + b"." + kwargs["userAgent"].encode("utf-8")).hexdigest()
            return ((userID == storedUserID) and (fingerprintHash == storedFingerprintHash))
        else:
            # expired
            return False

    elif (mode == "delete_expired_sessions"):
        cur.execute("DELETE FROM session WHERE expiry_date < SGT_NOW()")
        connection.commit()

    elif (mode == "if_session_exists"):
        sessionID = ["sessionID"]
        cur.execute("SELECT * FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        returnValue = cur.fetchone()
        if (returnValue):
            return True
        else:
            return False

    elif (mode == "delete_users_other_session"):
        # delete all session of a user except the current session id
        userID = kwargs["userID"]
        sessionID = ["sessionID"]
        cur.execute("DELETE FROM session WHERE user_id = %(userID)s AND session_id != %(sessionID)s", {"userID":userID, "session_id":sessionID})
        connection.commit()

    else:
        connection.close()
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
        connection.close()
        raise ValueError("You must specify a mode in the user_sql_operation function!")

    cur = connection.cursor()

    if (mode == "verify_userID_existence"):
        userID = kwargs["userID"]
        if (userID is None):
            connection.close()
            raise ValueError("You must specify a userID when verifying the userID!")
        cur.execute("SELECT * FROM user WHERE id=%(userID)s", {"userID":userID})
        return bool(cur.fetchone())

    elif (mode == "email_verified"):
        userID = kwargs["userID"]
        getEmail = kwargs.get("email") or False
        if (userID is None):
            connection.close()
            raise ValueError("You must specify a userID when verifying the userID!")

        cur.execute("SELECT email_verified, email FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        if (matched is None):
            return None
        return matched if (getEmail) else matched[0]

    elif (mode == "remove_unverified_users_more_than_30_days"):
        cur.execute("DELETE FROM user WHERE email_verified=FALSE AND created_date < SGT_NOW() - INTERVAL 30 DAY")
        connection.commit()

    elif (mode == "update_email_to_verified"):
        userID = kwargs["userID"]
        if (userID is None):
            connection.close()
            raise ValueError("You must specify a userID when verifying the userID!")
        cur.execute("UPDATE user SET email_verified = TRUE WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "re-encrypt_data_in_database"):
        # Used for re-encrypting all the encrypted data in the database at the last day of every month due to 30 days key rotations.
        current_app.config["MAINTENANCE_MODE"] = True
        cur.execute("SELECT u.id, u.password, tfa.token FROM user AS u LEFT OUTER JOIN twofa_token AS tfa ON u.id=tfa.user_id;")
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
                except (DecryptionError):
                    connection.close()
                    write_log_entry(
                        logMessage="Re-encryption of password hash has failed...",
                        severity="ALERT"
                    )
                    return
                cur.execute("UPDATE user SET password = %(password)s WHERE id=%(userID)s", {"password":newEncryptedPasswordHash, "userID":userID})
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
                    connection.close()
                    write_log_entry(
                        logMessage="Re-encryption of 2FA token has failed...",
                        severity="ALERT"
                    )
                    return
                cur.execute("UPDATE twofa_token SET token = %(token)s WHERE user_id=%(userID)s", {"token":newEncryptedToken, "userID":userID})
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
            "INSERT INTO user VALUES (%(userID)s, %(role)s, %(usernameInput)s, %(emailInput)s, FALSE, %(passwordInput)s, %(profile_image)s, SGT_NOW(),%(cart_courses)s, %(purchased_courses)s)",
            {"userID":userID, "role":roleID, "usernameInput":usernameInput, "emailInput":emailInput, "passwordInput":passwordInput, "profile_image":None,"cart_courses":"[]", "purchased_courses":"[]"}
        )
        connection.commit()

        user_ip_addresses_sql_operation(connection=connection, mode="add_ip_address", userID=userID, ipAddress=kwargs["ipAddress"])

        return userID

    elif (mode == "check_if_using_google_oauth2"):
        userID = kwargs["userID"]
        cur.execute("SELECT password FROM user WHERE id=%(userID)s", {"userID":userID})
        password = cur.fetchone()
        if (password is None):
            connection.close()
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
            cur.execute("CALL get_role_id(%(Student)s)", {"Student":"Student"})
            roleID = cur.fetchone()[0]

            cur.execute(
                "INSERT INTO user VALUES (%(userID)s, %(role)s, %(usernameInput)s, %(emailInput)s, TRUE, NULL, %(profile_image)s, SGT_NOW(), %(cart_courses)s, %(purchased_courses)s)",
                {"userID":userID, "role":roleID, "usernameInput":username, "emailInput":email, "profile_image":googleProfilePic, "cart_courses":"[]", "purchased_courses":"[]"}
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

        cur.execute("SELECT id, password, username, role, email_verified FROM user WHERE email=%(emailInput)s", {"emailInput":emailInput})
        matched = cur.fetchone()

        if (matched is None):
            connection.close()
            raise EmailDoesNotExistError("Email does not exist!")

        username = matched[2]
        roleID = matched[3]
        encryptedPasswordHash = matched[1]
        userID = matched[0]
        emailVerified = matched[4]

        if (encryptedPasswordHash is None):
            connection.close()
            raise UserIsUsingOauth2Error("User is using Google OAuth2, please use Google OAuth2 to login!")

        cur.execute("SELECT attempts FROM login_attempts WHERE user_id= %(userID)s", {"userID":userID})
        loginAttempts = cur.fetchone()

        requestIpAddress = kwargs["ipAddress"]
        ipAddressList = user_ip_addresses_sql_operation(connection=connection, mode="get_ip_addresses", userID=userID, ipAddress=requestIpAddress)

        # send an email to the authentic user if their account got locked
        if (loginAttempts and loginAttempts[0] > CONSTANTS.MAX_LOGIN_ATTEMPTS):
            resetAttempts = login_attempts_sql_operation(connection=connection, mode="reset_attempts_past_reset_date_for_user", userID=userID)

            # If the user has exceeded the maximum number of login attempts,
            # but the timeout is not up yet...
            if (not resetAttempts):
                connection.close()
                send_unlock_locked_acc_email(email=emailInput, userID=userID)
                raise AccountLockedError("Account is locked!")

        # send verification email if the user has not verified their email
        if (not emailVerified):
            connection.close()
            send_verification_email(email=emailInput, userID=userID, username=username)
            raise EmailNotVerifiedError("Email has not been verified, please verify your email!")

        newIpAddress = False
        decryptedPasswordHash = symmetric_decrypt(ciphertext=encryptedPasswordHash, keyID=CONSTANTS.PEPPER_KEY_ID)
        try:
            if (CONSTANTS.PH.verify(decryptedPasswordHash, passwordInput)):
                # check if the login request is from the same IP address as the one that made the request
                if (requestIpAddress not in ipAddressList):
                    newIpAddress = True

                # convert the role id to a readable format
                cur.execute("CALL get_role_name(%(roleID)s)", {"roleID":roleID})
                roleName = cur.fetchone()[0]

                return (userID, newIpAddress, username, roleName)
        except (VerifyMismatchError):
            connection.close()
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "find_user_for_reset_password"):
        email = kwargs["email"]
        cur.execute("SELECT id, password FROM user WHERE email=%(email)s", {"email":email})
        matched = cur.fetchone()
        return matched

    elif (mode == "get_user_data"):
        userID = kwargs["userID"]
        cur.execute("SELECT * FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        if (matched is None):
            return False

        cur.execute("CALL get_role_name(%(matched)s)", {"matched":matched[1]})
        roleMatched = cur.fetchone()
        matched = list(matched)
        matched[1] = roleMatched[0]

        return tuple(matched)

    elif (mode == "change_profile_picture"):
        userID = kwargs["userID"]
        profileImagePath = kwargs.get("profileImagePath")
        cur.execute("UPDATE user SET profile_image=%(profile_image)s WHERE id=%(userID)s", {"profile_image":profileImagePath, "userID":userID})
        connection.commit()

    elif (mode == "delete_profile_picture"):
        userID = kwargs["userID"]
        cur.execute("UPDATE user SET profile_image=%(profile_image)s WHERE id=%(userID)s", {"profile_image":None, "userID":userID})
        connection.commit()

    elif (mode == "change_username"):
        userID = kwargs["userID"]
        usernameInput = kwargs.get("username")
        cur.execute("SELECT * FROM user WHERE username=%(username)s", {"username":usernameInput})
        reusedUsername = bool(cur.fetchone())

        if (reusedUsername):
            connection.close()
            raise ReusedUsernameError(f"The username {usernameInput} is already in use!")

        cur.execute("UPDATE user SET username=%(usernameInput)s WHERE id=%(userID)s", {"usernameInput": usernameInput, "userID": userID})
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
                connection.close()
                raise SameAsOldEmailError(f"The email {emailInput} is the same as the old email!")
            else:
                connection.close()
                raise EmailAlreadyInUseError(f"The email {emailInput} is already in use!")

        cur.execute("SELECT password FROM user WHERE id=%(userID)s", {"userID":userID})
        currentPassword = symmetric_decrypt(ciphertext=cur.fetchone()[0], keyID=CONSTANTS.PEPPER_KEY_ID)
        try:
            if (CONSTANTS.PH.verify(currentPassword, currentPasswordInput)):
                cur.execute("UPDATE user SET email=%(emailInput)s, email_verified=FALSE WHERE id=%(userID)s", {"emailInput": emailInput, "userID":userID})
                connection.commit()
                send_verification_email(email=emailInput, userID=userID)
        except (VerifyMismatchError):
            connection.close()
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
                    connection.close()
                    raise PwdTooShortError(f"The password must be at least {CONSTANTS.MIN_PASSWORD_LENGTH} characters long!")

                if (len(passwordInput) > CONSTANTS.MAX_PASSWORD_LENGTH):
                    connection.close()
                    raise PwdTooLongError(f"The password must be less than {CONSTANTS.MAX_PASSWORD_LENGTH} characters long!")

                if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
                    connection.close()
                    raise PwdTooWeakError("The password is too weak!")

                cur.execute(
                    "UPDATE user SET password=%(password)s WHERE id=%(userID)s",
                    {"password": symmetric_encrypt(plaintext=CONSTANTS.PH.hash(passwordInput), keyID=CONSTANTS.PEPPER_KEY_ID), "userID": userID}
                )
                connection.commit()
        except (VerifyMismatchError):
            connection.close()
            raise ChangePwdError("The old password is incorrect!")

    elif (mode == "reset_password"):
        userID = kwargs["userID"]
        newPassword = kwargs["newPassword"]

        cur.execute(
            "UPDATE user SET password=%(password)s WHERE id=%(userID)s",
            {"password": symmetric_encrypt(plaintext=CONSTANTS.PH.hash(newPassword), keyID=CONSTANTS.PEPPER_KEY_ID), "userID": userID}
        )
        connection.commit()

    elif (mode == "delete_user"):
        userID = kwargs["userID"]
        cur.execute("DELETE FROM user WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "update_to_teacher"):
        userID = kwargs["userID"]

        cur.execute("SELECT role FROM user WHERE id=%(userID)s", {"userID":userID})
        currentRoleID = cur.fetchone()[0]
        cur.execute("CALL get_role_name(%(currentRoleID)s)", {"currentRoleID":currentRoleID})
        currentRole = cur.fetchone()[0]

        isTeacher = False if (currentRole != "Teacher") else True
        if (not isTeacher):
            cur.execute("CALL get_role_id(%(Teacher)s)", {"Teacher":"Teacher"})
            teacherRoleID = cur.fetchone()[0]
            cur.execute("UPDATE user SET role=%(teacherRoleID)s WHERE id=%(userID)s", {"teacherRoleID": teacherRoleID, "userID":userID})
            connection.commit()
        else:
            connection.close()
            raise IsAlreadyTeacherError("The user is already a teacher!")

    elif (mode == "get_user_purchases"):
        userID = kwargs["userID"]
        cur.execute("SELECT purchased_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        cur.execute("SELECT JSON_ARRAY('userID', %(userID)s) FROM user", {"userID":userID})
        return json.loads(cur.fetchone()[0])

    elif mode == "get_user_cart":
        userID = kwargs["userID"]
        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        return json.loads(cur.fetchone()[0])

    elif mode == "add_to_cart":
        userID = kwargs["userID"]
        courseID = kwargs["courseID"]

        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        cartCourseIDs = json.loads(cur.fetchone()[0])

        cur.execute("SELECT purchased_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        purchasedCourseIDs = json.loads(cur.fetchone()[0])

        if courseID not in cartCourseIDs and courseID not in purchasedCourseIDs:
            cartCourseIDs.append(courseID)
            cur.execute("UPDATE user SET cart_courses=%(cart)s WHERE id=%(userID)s", {"cart":json.dumps(cartCourseIDs),"userID":userID})
            connection.commit()

    elif mode == "remove_from_cart":
        userID = kwargs["userID"]
        courseID = kwargs["courseID"]

        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        cartCourseIDs = json.loads(cur.fetchone()[0])

        if courseID in cartCourseIDs:
            cartCourseIDs.remove(courseID)
            cur.execute("UPDATE user SET cart_courses=%(cart)s WHERE id=%(userID)s", {"cart":json.dumps(cartCourseIDs),"userID":userID})
            connection.commit()

    elif mode == "purchase_courses":

        userID = kwargs["userID"]
        cartCourseIDs = kwargs["cartCourseIDs"]

        cur.execute("SELECT purchased_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        purchasedCourseIDs = json.loads(cur.fetchone()[0])

        for courseID in cartCourseIDs:

            if courseID not in purchasedCourseIDs:
                purchasedCourseIDs.append(courseID)

        # Add to purchases
        cur.execute("UPDATE user SET purchased_courses=%(purchased)s WHERE id=%(userID)s", {"purchased":json.dumps(purchasedCourseIDs), "userID":userID})

        # Empty cart
        cur.execute("UPDATE user SET cart_courses='[]' WHERE id=%(userID)s", {"userID":userID})

        connection.commit()

    else:
        connection.close()
        raise ValueError("Invalid mode in the user_sql_operation function!")

def course_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs)  -> Union[list, tuple, bool, None]:
    """
    Do CRUD operations on the course table

    insert keywords: teacherID

    get_course_data keywords: courseID

    edit keywords:
    """
    if (not mode):
        connection.close()
        raise ValueError("You must specify a mode in the course_sql_operation function!")

    cur = connection.cursor()

    if (mode == "insert"):
        course_id = kwargs["courseID"]
        teacher_id = kwargs["teacherID"]
        course_name = kwargs["courseName"]
        course_description = kwargs.get("courseDescription")
        course_image_path = kwargs.get("courseImagePath")
        course_price = kwargs["coursePrice"]
        course_category = kwargs["courseCategory"]
        video_path = kwargs["videoPath"]
        course_total_rating = 0
        course_rating_count = 0

        cur.execute(
            "INSERT INTO course VALUES (%(course_id)s, %(teacher_id)s, %(course_name)s, %(course_description)s, %(course_image_path)s, %(course_price)s, %(course_category)s, %(course_total_rating)s, %(course_rating_count)s, SGT_NOW(), %(video_path)s)",
            {"course_id":course_id, "teacher_id":teacher_id, "course_name":course_name, "course_description":course_description, "course_image_path":course_image_path, "course_price":course_price, "course_category":course_category, "course_total_rating":course_total_rating, "course_rating_count":course_rating_count, "video_path":video_path}
        )
        connection.commit()

    elif (mode == "get_course_data"):
        course_id = kwargs["courseID"]
        print('Course_ID:', course_id)
        cur.execute("SELECT * FROM course WHERE course_id=%(course_id)s", {"course_id":course_id})
        matched = cur.fetchone()
        print('Matched:', matched)
        if (not matched):
            return False
        return matched

    # Added just in case want to do updating

    elif (mode == "update_course_title"):
        course_id = kwargs["courseID"]
        course_title = kwargs["courseTitle"]
        cur.execute("UPDATE course SET course_name=%(course_name)s WHERE course_id=%(courseID)s", {"course_name":course_title, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_description"):
        course_id = kwargs["courseID"]
        course_description = kwargs["courseDescription"]
        cur.execute("UPDATE course SET course_description=%(course_description)s WHERE course_id=%(courseID)s", {"course_description":course_description, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_category"):
        course_id = kwargs["courseID"]
        course_category = kwargs["course_category"]
        cur.execute("UPDATE course SET course_category=%(course_category)s WHERE course_id=%(courseID)s", {"course_category":course_category, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_price"):
        course_id = kwargs["courseID"]
        course_price = kwargs.get("coursePrice")
        cur.execute("UPDATE course SET course_price=%(course_price)s WHERE course_id=%(courseID)s", {"course_price":course_price, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_thumbnail"):
        course_id = kwargs["courseID"]
        course_image_path = kwargs["courseImagePath"]
        cur.execute("UPDATE course SET course_image_path=%(course_image_path)s WHERE course_id=%(courseID)s", {"course_image_path":course_image_path, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_video"):
        course_id = kwargs["courseID"]
        video_path = kwargs["videoPath"]
        cur.execute("UPDATE course SET video_path=%(video_path)s WHERE course_id=%(courseID)s", {"video_path":video_path, "courseID":course_id})
        connection.commit()

    elif (mode == "delete"):
        course_id = kwargs["courseID"]
        cur.execute("DELETE FROM course WHERE course_id=%(course_id)s", {"course_id":course_id})
        connection.commit()

    elif (mode == "get_all_courses"):
        teacher_id = kwargs["teacherID"]
        courseList = []
        cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE teacher_id=%(teacher_id)s", {"teacher_id":teacher_id})
        resultsList = cur.fetchall()
        
        if (len(resultsList) == 0):
            return courseList
        #Password will be null if using Google Auth
        cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacher_id)s AND password IS NULL", {"teacher_id":teacher_id})
        teacherData = cur.fetchone()
        if (teacherData):
            teacherUsername, teacherProfile = teacherData[0], teacherData[1]
            teacherProfile = (teacherProfile, True)
            for tupleInfo in resultsList:
                courseList.append(Course(((teacherUsername, teacherProfile), tupleInfo), truncateData=True))
        else:
            teacherUsername, teacherProfile = teacherData[0], teacherData[1]
            teacherProfile = (teacherProfile, False)
            for tupleInfo in resultsList:
                courseList.append(Course(((teacherUsername, teacherProfile), tupleInfo), truncateData=True))            

        return courseList

    elif (mode == "get_all_courses_by_teacher"):
        teacherID = kwargs["teacherID"]
        pageNum = kwargs["pageNum"]
        offset = (pageNum - 1) * 10
        # Not using offset as it will get noticeably slower with more courses
        cur.execute("CALL paginate_courses(%(teacher_id)s, %(offset)s)", {"teacherID":teacherID, "pageNum":offset})
        resultsList = cur.fetchall()
        if (resultsList is None):
            return []

        teacherProfile = get_dicebear_image(res[2]) if (not res[3]) \
                                                    else res[3]

        courseList = []
        for tupleInfo in resultsList:
            courseList.append(
                CourseInfo(tupleInfo, profilePic=teacherProfile, truncateData=True)
            )
        return courseList

    elif (mode == "get_3_latest_courses" or mode == "get_3_highly_rated_courses"):
        teacherID = kwargs.get("teacherID")

        if (mode == "get_3_latest_courses"):
            # get the latest 3 courses
            if (teacherID is None):
                cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course ORDER BY date_created DESC LIMIT 3")
            else:
                cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE teacher_id=%(teacherID)s ORDER BY date_created DESC LIMIT 3", {"teacherID":teacherID})
        else:
            # get top 3 highly rated courses
            if (teacherID is None):
                cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course ORDER BY (course_total_rating/course_rating_count) DESC LIMIT 3")
            else:
                cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE teacher_id=%(teacherID)s ORDER BY (course_total_rating/course_rating_count) DESC LIMIT 3", {"teacherID":teacherID})

        matchedList = cur.fetchall()
        if (not matchedList):
            return []
        else:
            # e.g. [(("Daniel", "daniel_profile_image"), (course_id, teacher_name, course_name,...))]
            courseInfoList = []
            # get the teacher name for each course
            if (not teacherID):
                teacherIDList = [teacherID[1] for teacherID in matchedList]
                for i, teacherID in enumerate(teacherIDList):
                    cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
                    res = cur.fetchone()
                    teacherUsername = res[0]
                    teacherProfile = res[1]
                    teacherProfile = (
                        get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                   else (teacherProfile, False
                    )
                    courseInfoList.append(
                        Course(((teacherUsername, teacherProfile), matchedList[i]), truncateData=True)
                    )
                return courseInfoList
            else:
                cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
                res = cur.fetchone()
                teacherUsername = res[0]
                teacherProfile = res[1]
                teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                            else (teacherProfile, False)
                for tupleInfo in matchedList:
                    courseInfoList.append(
                        Course(((teacherUsername, teacherProfile), tupleInfo), truncateData=True)
                    )

                if (kwargs.get("getTeacherUsername")):
                    return (courseInfoList, res[0])

                return courseInfoList

    elif (mode == "search"):
        searchInput = kwargs.get("searchInput", "")
        resultsList = []

        cur.execute("CALL search_for(%(searchInput)s)", {"searchInput":searchInput})
        foundResults = cur.fetchall()

        teacherIDList = [teacherID[1] for teacherID in foundResults]
        for i, teacherID in enumerate(teacherIDList):
            cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
            res = cur.fetchone()
            teacherUsername = res[0]
            teacherProfile = res[1]
            teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                         else (teacherProfile, False)
            if ("googleusercontent" in teacherProfile[0]):
                teacherProfile = (res[1], True)

            resultsList.append(Course(((teacherUsername, teacherProfile), foundResults[i]), truncateData=True))

        return resultsList

    else:
        connection.close()
        raise ValueError("Invalid mode in the session_sql_operation function!")

def review_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the purchased table

    revieve_user_review keywords: userID, courseID,
    insert keywords: userID, courseID, courseRating, CourseReview
    retrieve_all keywords: courseID

    """
    if mode is None:
        connection.close()
        raise ValueError("You must specify a mode in the review_sql_operation function!")

    cur = connection.cursor()

    courseID = kwargs["courseID"]

    if mode == "retrieve_user_review":
        userID = kwargs["userID"]
        cur.execute("SELECT course_rating FROM review WHERE user_id = %(userID)s AND course_id = %(courseID)s", {"userID":userID, "courseID":courseID})
        review_list = cur.fetchall()
        return review_list

    elif mode == "insert":
        userID = kwargs["userID"]
        courseRating = kwargs["courseRating"]
        courseReview = kwargs["courseReview"]
        #reviewDates = kwargs.get("reviewDates")
        cur.execute("INSERT INTO review VALUES (%(userID)s, %(courseID)s, %(courseRating)s, %(courseReview)s, %(reviewDate)s)", {"userID":userID, "courseID":courseID, "courseRating":courseRating, "courseReview":courseReview})
        connection.commit()

    elif mode == "retrieve_all":
        cur.execute("SELECT r.user_id, r.course_id, r.course_rating, r.course_review, r.review_date, u.username FROM review r INNER JOIN user u ON r.user_id = u.id WHERE r.course_id = %(courseID)s", {"courseID":courseID})
        review_list = cur.fetchall()
        return review_list if (review_list is not None) else []

    else:
        connection.close()
        raise ValueError("Invalid mode in the review_sql_operation function!")