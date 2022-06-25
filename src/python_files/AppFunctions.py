"""
This python file contains all the functions that requires the import of the
flask web application's app variable from app.py.
"""

# import Flask web application configs
from app import app
from flask import url_for

# import python standard libraries
import json
from typing import Union

# import third party libraries
from dicebear import DAvatar, DStyle
from argon2.exceptions import VerifyMismatchError
import pymysql.err as MySQLErrors
from pymysql.connections import Connection as MySQLConnection

# for google oauth login
from google_auth_oauthlib.flow import Flow

# import local python files
from .Course import Course
from .Errors import *
from .NormalFunctions import generate_id, pwd_has_been_pwned, pwd_is_strong, \
                             symmetric_encrypt, symmetric_decrypt, create_symmetric_key
from .ConstantsInit import GOOGLE_CREDENTIALS, PH, MAX_PASSWORD_LENGTH, IPINFO_HANDLER
from .MySQLInit import mysql_init_tables as MySQLInitialise, get_mysql_connection

"""------------------------------ Define Constants ------------------------------"""

# for defining the maximum login attempts
# before locking a user account
MAX_LOGIN_ATTEMPTS = 10

"""------------------------------ End of Defining Constants ------------------------------"""

def accepted_image_extension(filename:str) -> bool:
    """
    Returns True if the image extension is accepted.
    """
    # if "." is in the filename and right split once and check if the extension is in the tuple of accepted extensions
    # e.g. "profile.test.png" -> ["profile.test", "png"]
    return ("." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_IMAGE_EXTENSIONS"])

def get_google_flow() -> Flow:
    """
    Returns the Google OAuth2 flow.
    """
    flow = Flow.from_client_config(
        GOOGLE_CREDENTIALS,
        [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
            "https://www.googleapis.com/auth/gmail.send" # for Google to send security alerts to the user's email
        ],
        redirect_uri=url_for("loginCallback", _external=True)
    )
    return flow

def add_session(userID:str) -> str:
    """
    Generate a 32 byte session ID and add it to the database.

    Args:
        - userID (str): The user ID of the user

    Returns:
        - The generated session ID (str)
    """
    # minimum requirement for a session ID:
    # https://owasp.deteact.com/cheat/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-length
    sessionID = generate_id() # using a 32 byte session ID

    sql_operation(table="session", mode="create_session", sessionID=sessionID, userID=userID)
    return sessionID

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
    imageSrcPath = userInfo[5]
    if (imageSrcPath is None):
        imageSrcPath = get_dicebear_image(userInfo[2])
    return imageSrcPath if (not returnUserInfo) else (imageSrcPath, userInfo)

def get_dicebear_image(username:str) -> str:
    """
    Returns a random dicebear image from the database

    Args:
        - username: The username of the user
    """
    av = DAvatar(
        style=DStyle.initials,
        seed=username,
        options=app.config["DICEBEAR_OPTIONS"]
    )
    return av.url_svg

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

    # uses Google Cloud SQL Public Address if debug mode is False else uses localhost

    try:
        con = get_mysql_connection(debug=app.config["DEBUG_FLAG"])
    except (MySQLErrors.OperationalError):
        print("Database Not Found...")
        print("Creating Database...")
        con = MySQLInitialise(debug=app.config["DEBUG_FLAG"])
        print("Created the neccessary tables for the database!\n")

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
        else:
            raise ValueError("Invalid table name")
    except (MySQLErrors.IntegrityError, MySQLErrors.OperationalError, MySQLErrors.InternalError, MySQLErrors.DataError) as e:
        # to ensure that the connection is closed even if an error with mysql occurs
        print("Error caught:")
        print(e)

    con.close()
    return returnValue

def user_ip_addresses_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) ->  Union[list, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the user_ip_addresses_sql_operation function!")

    cur = connection.cursor()

    # INET6_ATON and INET6_NTOA are functions in-built to mysql and are used to convert IPv4 and IPv6 addresses to and from a binary string
    # https://dev.mysql.com/doc/refman/8.0/en/miscellaneous-functions.html#function_inet6-ntoa
    if (mode == "add_ip_address"):
        userID = kwargs.get("userID")
        ipAddress = kwargs.get("ipAddress")
        ipDetails = kwargs.get("ipDetails") or json.dumps(IPINFO_HANDLER.getDetails(ipAddress).all)

        cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address, ip_address_details) VALUES (%(userID)s, INET6_ATON(%(ipAddress)s), %(ipDetails)s)", {"userID":userID, "ipAddress":ipAddress, "ipDetails":ipDetails})
        connection.commit()

    elif (mode == "get_ip_addresses"):
        userID = kwargs.get("userID")

        cur.execute("SELECT INET6_NTOA(ip_address) FROM user_ip_addresses WHERE user_id = %(userID)s", {"userID":userID})
        returnValue = cur.fetchall()
        ipAddressList = [ipAddress[0] for ipAddress in returnValue]
        return ipAddressList

    elif (mode == "add_ip_address_only_if_unique"):
        userID = kwargs.get("userID")
        ipAddress = kwargs.get("ipAddress")
        ipDetails = kwargs.get("ipDetails") or json.dumps(IPINFO_HANDLER.getDetails(ipAddress).all)

        cur.execute("SELECT COUNT(*) FROM user_ip_addresses WHERE user_id = %(userID)s AND INET6_NTOA(ip_address) = %(ipAddress)s", {"userID":userID, "ipAddress":ipAddress})
        if (cur.fetchone()[0] == 0):
            cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address, ip_address_details) VALUES (%(userID)s, INET6_ATON(%(ipAddress)s), %(ipDetails)s)", {"userID":userID, "ipAddress":ipAddress, "ipDetails":ipDetails})
            connection.commit()

    elif (mode == "remove_last_accessed_more_than_10_days"):
        cur.execute("DELETE FROM user_ip_addresses WHERE DATEDIFF(NOW(), last_accessed) > 10")
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
        token = kwargs.get("token")
        userID = kwargs.get("userID")

        # get symmetric key name from user table
        cur.execute("SELECT key_name FROM user WHERE id = %(userID)s", {"userID":userID})
        keyName = cur.fetchone()[0]
        token = symmetric_encrypt(plaintext=token, keyID=keyName)

        cur.execute("INSERT INTO twofa_token (token, user_id) VALUES (%(token)s, %(userID)s)", {"token":token, "userID":userID})
        connection.commit()

    elif (mode == "get_token"):
        userID = kwargs.get("userID")
        cur.execute("SELECT token FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        matchedToken = cur.fetchone()
        if (matchedToken is None):
            connection.close()
            raise No2FATokenError("No 2FA OTP found for this user!")

        # get symmetric key name from user table
        cur.execute("SELECT key_name FROM user WHERE id = %(userID)s", {"userID":userID})
        keyName = cur.fetchone()[0]

        # decrypt the encrypted secret token for 2fa
        token = symmetric_decrypt(ciphertext=matchedToken[0], keyID=keyName)
        return token

    elif (mode == "check_if_user_has_2fa"):
        userID = kwargs.get("userID")
        cur.execute("SELECT token FROM twofa_token WHERE user_id = %(userID)s", {"userID":userID})
        matchedToken = cur.fetchone()
        return True if (matchedToken is not None) else False

    elif (mode == "delete_token"):
        userID = kwargs.get("userID")
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
        emailInput = kwargs.get("email")
        cur.execute("SELECT id FROM user WHERE email = %(emailInput)s", {"emailInput":emailInput})
        userID = cur.fetchone()
        if (userID is None):
            connection.close()
            raise EmailDoesNotExistError("Email does not exist!")

        userID = userID[0]
        cur.execute("SELECT attempts, reset_date FROM login_attempts WHERE user_id = %(userID)s", {"userID":userID})
        attempts = cur.fetchone()
        if (attempts is None):
            cur.execute("INSERT INTO login_attempts (user_id, attempts, reset_date) VALUES (%(userID)s, %(attempts)s, NOW() + INTERVAL %(intervalMins)s MINUTE)", {"userID":userID, "attempts":1, "intervalMins":app.config["LOCKED_ACCOUNT_DURATION"]})
        else:
            cur.execute("SELECT NOW()")
            now = cur.fetchone()[0]
            # comparing the reset datetime with the current datetime
            if (attempts[1] > now):
                # if not past the reset datetime
                currentAttempts = attempts[0]
            else:
                # if past the reset datetime, reset the attempts to 0
                currentAttempts = 0

            if (currentAttempts > MAX_LOGIN_ATTEMPTS):
                # if reached max attempts per account
                connection.close()
                raise AccountLockedError("User have exceeded the maximum number of password attempts!")

            cur.execute("UPDATE login_attempts SET attempts = %(currentAttempts)s, reset_date = NOW() + INTERVAL %(intervalMins)s MINUTE WHERE user_id = %(userID)s",{"currentAttempts":currentAttempts+1, "intervalMins":app.config["LOCKED_ACCOUNT_DURATION"], "userID":userID})
        connection.commit()

    elif (mode == "reset_user_attempts"):
        userID = kwargs.get("userID")
        cur.execute("DELETE FROM login_attempts WHERE user_id = %(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "reset_attempts_past_reset_date"):
        cur.execute("DELETE FROM login_attempts WHERE reset_date < NOW()")
        connection.commit()

    else:
        connection.close()
        raise ValueError("Invalid mode in the login_attempts_sql_operation function!")

def session_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[str, bool, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the session_sql_operation function!")

    cur = connection.cursor()

    if (mode == "create_session"):
        sessionID = kwargs.get("sessionID")
        userID = kwargs.get("userID")
        cur.execute("INSERT INTO session VALUES (%(sessionID)s, %(userID)s, NOW() + INTERVAL %(intervalMins)s MINUTE)", {"sessionID":sessionID, "userID":userID, "intervalMins":app.config["SESSION_EXPIRY_INTERVALS"]})
        connection.commit()

    elif (mode == "get_user_id"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT user_id FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        userID = cur.fetchone()[0]
        return userID

    elif (mode == "get_session"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT * FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        returnValue = cur.fetchone()
        return returnValue

    elif (mode == "delete_session"):
        sessionID = kwargs.get("sessionID")
        cur.execute("DELETE FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        connection.commit()

    elif (mode == "update_session"):
        sessionID = kwargs.get("sessionID")
        cur.execute("UPDATE session SET expiry_date = NOW() + INTERVAL %(intervalMins)s MINUTE WHERE session_id = %(sessionID)s", {"intervalMins": app.config["SESSION_EXPIRY_INTERVALS"], "sessionID": sessionID})
        connection.commit()

    elif (mode == "check_if_valid"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT user_id, expiry_date FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        result = cur.fetchone()
        expiryDate = result[1]
        cur.execute("SELECT NOW()")
        now = cur.fetchone()[0]
        if (expiryDate >= now):
            # not expired, check if the userID matches the sessionID
            return kwargs.get("userID") == result[0]
        else:
            # expired
            return False

    elif (mode == "delete_expired_sessions"):
        cur.execute("DELETE FROM session WHERE expiry_date < NOW()")
        connection.commit()

    elif (mode == "if_session_exists"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT * FROM session WHERE session_id = %(sessionID)s", {"sessionID":sessionID})
        returnValue = cur.fetchone()
        if (returnValue):
            return True
        else:
            return False

    elif (mode == "delete_users_other_session"):
        # delete all session of a user except the current session id
        userID = kwargs.get("userID")
        sessionID = kwargs.get("sessionID")
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
        userID = kwargs.get("userID")
        if (userID is None):
            connection.close()
            raise ValueError("You must specify a userID when verifying the userID!")
        cur.execute("SELECT * FROM user WHERE id=%(userID)s", {"userID":userID})
        return bool(cur.fetchone())

    elif (mode == "signup"):
        emailInput = kwargs.get("email")
        usernameInput = kwargs.get("username")

        cur.execute("SELECT * FROM user WHERE email=%(emailInput)s", {"emailInput":emailInput})
        emailDupe = bool(cur.fetchone())

        cur.execute("SELECT * FROM user WHERE username=%(usernameInput)s", {"usernameInput":usernameInput})
        usernameDupes = bool(cur.fetchone())

        if (emailDupe or usernameDupes):
            return (emailDupe, usernameDupes)

        # create symmetric key for the user and store it in Google Cloud KMS API
        if (app.config["DEBUG_FLAG"]):
            keyName = "test-key"
        else:
            keyName = f"key-{generate_id()}"
            create_symmetric_key(keyName=keyName)

        # add to the MySQL database
        userID = generate_id()
        passwordInput = symmetric_encrypt(plaintext=kwargs["password"], keyID=keyName) # encrypt the password hash

        cur.execute("CALL get_role_id(%(Student)s)", {"Student":"Student"})
        roleID = cur.fetchone()[0]
        # cur.callproc("get_role_id", ("Student",))
        # for result in cur.stored_results():
        #     roleID = result.fetchone()[0]

        cur.execute(
            "INSERT INTO user VALUES (%(userID)s, %(role)s, %(usernameInput)s, %(emailInput)s, %(passwordInput)s, %(profile_image)s, NOW(), %(key_name)s,%(cart_courses)s, %(purchased_courses)s)",
            {"userID":userID, "role":roleID, "usernameInput":usernameInput, "emailInput":emailInput, "passwordInput":passwordInput, "profile_image":None, "key_name": keyName,"cart_courses":"[]", "purchased_courses":"[]"}
        )
        connection.commit()

        user_ip_addresses_sql_operation(connection=connection, mode="add_ip_address", userID=userID, ipAddress=kwargs["ipAddress"])

        return userID

    elif (mode == "check_if_using_google_oauth2"):
        userID = kwargs.get("userID")
        cur.execute("SELECT password, id FROM user WHERE id=%(userID)s", {"userID":userID})
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
        userID = kwargs.get("userID")
        username = kwargs.get("username")
        email = kwargs.get("email")
        googleProfilePic = kwargs.get("googleProfilePic")

        # check if the email exists
        cur.execute("SELECT * FROM user WHERE email=%(email)s", {"email":email})
        matched = cur.fetchone()
        if (matched is None):
            # user does not exist, create new user with the given information

            # get role id
            cur.execute("CALL get_role_id(%(Student)s)", {"Student":"Student"})
            roleID = cur.fetchone()[0]
            # cur.callproc("get_role_id", ("Student",))
            # for result in cur.stored_results():
            #     roleID = result.fetchone()[0]

            # create symmetric key for the user and store it in Google Cloud KMS API
            if (app.config["DEBUG_FLAG"]):
                keyName = "test-key"
            else:
                keyName = f"key-{generate_id()}"
                create_symmetric_key(keyName=keyName)

            cur.execute(
                "INSERT INTO user VALUES (%(userID)s, %(role)s, %(usernameInput)s, %(emailInput)s, %(passwordInput)s, %(profile_image)s, NOW(), %(key_name)s, %(cart_courses)s, %(purchased_courses)s)",
                {"userID":userID, "role":roleID, "usernameInput":username, "emailInput":email, "passwordInput":None, "profile_image":googleProfilePic, "key_name": keyName, "cart_courses":"[]", "purchased_courses":"[]"}
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
                # cur.callproc("get_role_name", (matched[1],))
                # for result in cur.stored_results():
                #     roleName = result.fetchone()[0]
                return (matched[0], roleName)

    elif (mode == "login"):
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        cur.execute("SELECT id, password, key_name, username, role FROM user WHERE email=%(emailInput)s", {"emailInput":emailInput})
        matched = cur.fetchone()
        if (not matched):
            connection.close()
            raise EmailDoesNotExistError("Email does not exist!")

        if (matched[1] is None):
            connection.close()
            raise UserIsUsingOauth2Error("User is using Google OAuth2, please use Google OAuth2 to login!")

        cur.execute("SELECT attempts FROM login_attempts WHERE user_id= %(userID)s", {"userID":matched[0]})
        lockedAccount = cur.fetchone()

        requestIpAddress = kwargs["ipAddress"]
        ipAddressList = user_ip_addresses_sql_operation(connection=connection, mode="get_ip_addresses", userID=matched[0], ipAddress=requestIpAddress)

        if (lockedAccount):
            if (lockedAccount[0] > MAX_LOGIN_ATTEMPTS):
                connection.close()
                raise AccountLockedError("Account is locked!")
            else:
                # reset the attempts
                cur.execute("DELETE FROM login_attempts WHERE user_id=%(userID)s", {"userID":matched[0]})
                connection.commit()

        newIpAddress = False
        decryptedPasswordHash = symmetric_decrypt(ciphertext=matched[1], keyID=matched[2])
        try:
            if (PH.verify(decryptedPasswordHash, passwordInput)):
                # check if the login request is from the same IP address as the one that made the request
                if (requestIpAddress not in ipAddressList):
                    newIpAddress = True

                # convert the role id to a readable format
                cur.execute("CALL get_role_name(%(matched)s)", {"matched":matched[4]})
                roleName = cur.fetchone()[0]
                # cur.callproc("get_role_name", (matched[4],))
                # for result in cur.stored_results():
                #     roleName = result.fetchone()[0]

                # encrypt the password again as the encryption key will rotate every 30 days
                # so as to use the new key, we need to encrypt the password again every time the user logins in successfully
                encryptedPasswordHash = symmetric_encrypt(plaintext=decryptedPasswordHash, keyID=matched[2])
                cur.execute("UPDATE user SET password=%(password)s WHERE id=%(userID)s", \
                            {"password":encryptedPasswordHash, "userID":matched[0]})
                connection.commit()
                return (matched[0], newIpAddress, matched[3], roleName)
        except (VerifyMismatchError):
            connection.close()
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "find_user_for_reset_password"):
        email = kwargs.get("email")
        cur.execute("SELECT id, password FROM user WHERE email=%(email)s", {"email":email})
        matched = cur.fetchone()
        return matched

    elif (mode == "get_user_data"):
        userID = kwargs.get("userID")
        cur.execute("SELECT * FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        if (not matched):
            return False
        cur.execute("CALL get_role_name(%(matched)s)", {"matched":matched[1]})
        roleMatched = cur.fetchone()
        # cur.callproc("get_role_name", (matched[1],))
        # for result in cur.stored_results():
        #     roleMatched = result.fetchone()
        matched = list(matched)
        matched[1] = roleMatched[0]
        return tuple(matched)

    elif (mode == "change_profile_picture"):
        userID = kwargs.get("userID")
        profileImagePath = kwargs.get("profileImagePath")
        cur.execute("UPDATE user SET profile_image=%(profile_image)s WHERE id=%(userID)s", {"profile_image":profileImagePath, "userID":userID})
        connection.commit()

    elif (mode == "delete_profile_picture"):
        userID = kwargs.get("userID")
        cur.execute("UPDATE user SET profile_image=%(profile_image)s WHERE id=%(userID)s", {"profile_image":None, "userID":userID})
        connection.commit()

    elif (mode == "change_username"):
        userID = kwargs.get("userID")
        usernameInput = kwargs.get("username")
        cur.execute("SELECT * FROM user WHERE username=%(username)s", {"username":usernameInput})
        reusedUsername = bool(cur.fetchone())

        if (reusedUsername):
            connection.close()
            raise ReusedUsernameError(f"The username {usernameInput} is already in use!")

        cur.execute("UPDATE user SET username=%(usernameInput)s WHERE id=%(userID)s", {"usernameInput": usernameInput, "userID": userID})
        connection.commit()

    elif (mode == "change_email"):
        userID = kwargs.get("userID")
        currentPasswordInput = kwargs.get("currentPassword")
        emailInput = kwargs.get("email")

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

        cur.execute("SELECT password, key_name FROM user WHERE id=%(userID)s", {"userID":userID})
        currentPassword = cur.fetchone()

        try:
            if (PH.verify(symmetric_decrypt(ciphertext=currentPassword[0], keyID=currentPassword[1]), currentPasswordInput)):
                cur.execute("UPDATE user SET email=%(emailInput)s WHERE id=%(userID)s", {"emailInput": emailInput, "userID":userID})
                connection.commit()
        except (VerifyMismatchError):
            connection.close()
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "change_password"):
        userID = kwargs.get("userID")
        oldPasswordInput = kwargs.get("oldPassword") # to authenticate the changes
        passwordInput = kwargs.get("password")

        cur.execute("SELECT password, key_name FROM user WHERE id=%(userID)s", {"userID":userID})
        matched = cur.fetchone()
        keyName = matched[1]
        currentPasswordHash = symmetric_decrypt(ciphertext=matched[0], keyID=keyName)

        try:
            # check if the supplied old password matches the current password
            if (PH.verify(currentPasswordHash, oldPasswordInput)):
                if (len(passwordInput) < 10):
                    connection.close()
                    raise PwdTooShortError("The password must be at least 10 characters long!")

                if (len(passwordInput) > MAX_PASSWORD_LENGTH):
                    connection.close()
                    raise PwdTooLongError(f"The password must be less than {MAX_PASSWORD_LENGTH} characters long!")

                if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
                    connection.close()
                    raise PwdTooWeakError("The password is too weak!")

                cur.execute("UPDATE user SET password=%(password)s WHERE id=%(userID)s", {"password": symmetric_encrypt(plaintext=PH.hash(passwordInput), keyID=keyName), "userID": userID})
                connection.commit()
        except (VerifyMismatchError):
            connection.close()
            raise ChangePwdError("The old password is incorrect!")

    elif (mode == "reset_password"):
        userID = kwargs.get("userID")
        newPassword = kwargs.get("newPassword")

        cur.execute("SELECT key_name FROM user WHERE id=%(userID)s", {"userID":userID})
        keyName = cur.fetchone()[0]

        cur.execute("UPDATE user SET password=%(password)s WHERE id=%(userID)s", {"password": symmetric_encrypt(plaintext=PH.hash(newPassword), keyID=keyName), "userID": userID})
        connection.commit()

    elif (mode == "delete_user"):
        userID = kwargs.get("userID")
        cur.execute("DELETE FROM user WHERE id=%(userID)s", {"userID":userID})
        connection.commit()

    elif (mode == "update_to_teacher"):
        userID = kwargs.get("userID")

        cur.execute("SELECT role FROM user WHERE id=%(userID)s", {"userID":userID})
        currentRoleID = cur.fetchone()[0]
        cur.execute("CALL get_role_name(%(currentRoleID)s)", {"currentRoleID":currentRoleID})
        currentRole = cur.fetchone()[0]
        # cur.callproc("get_role_name", (currentRoleID,))
        # for result in cur.stored_results():
        #     currentRole = result.fetchone()[0]

        isTeacher = True if (currentRole == "Teacher") else False
        if (not isTeacher):
            cur.execute("CALL get_role_id(%(Teacher)s)", {"Teacher":"Teacher"})
            teacherRoleID = cur.fetchone()[0]
            # cur.callproc("get_role_id", ("Teacher",))
            # for result in cur.stored_results():
            #     teacherRoleID = result.fetchone()[0]
            cur.execute("UPDATE user SET role=%(teacherRoleID)s WHERE id=%(userID)s", {"teacherRoleID": teacherRoleID, "userID":userID})
            connection.commit()
        else:
            connection.close()
            raise IsAlreadyTeacherError("The user is already a teacher!")

    elif (mode == "get_user_purchases"):
        userID = kwargs.get("userID")
        cur.execute("SELECT purchased_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        return json.loads(cur.fetchone()[0])

    elif mode == "get_user_cart":
        userID = kwargs.get("userID")
        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        return json.loads(cur.fetchone()[0])

    elif mode == "add_to_cart":
        userID = kwargs.get("userID")
        courseID = kwargs.get("courseID")

        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        cartCourseIDs = json.loads(cur.fetchone()[0])

        cur.execute("SELECT purchased_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        purchasedCourseIDs = json.loads(cur.fetchone()[0])

        if courseID not in cartCourseIDs and courseID not in purchasedCourseIDs:
            cartCourseIDs.append(courseID)
            cur.execute("UPDATE user SET cart_courses=%(cart)s WHERE id=%(userID)s", {"cart":json.dumps(cartCourseIDs),"userID":userID})
            connection.commit()

    elif mode == "remove_from_cart":
        userID = kwargs.get("userID")
        courseID = kwargs.get("courseID")

        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        cartCourseIDs = json.loads(cur.fetchone()[0])

        if courseID in cartCourseIDs:
            cartCourseIDs.remove(courseID)
            cur.execute("UPDATE user SET cart_courses=%(cart)s WHERE id=%(userID)s", {"cart":json.dumps(cartCourseIDs),"userID":userID})
            connection.commit()

    elif mode == "purchase_courses":

        userID = kwargs.get("userID")

        cur.execute("SELECT cart_courses FROM user WHERE id=%(userID)s", {"userID":userID})
        cartCourseIDs = json.loads(cur.fetchone()[0])

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
        raise ValueError("Invalid mode in the session_sql_operation function!")

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
        course_id = kwargs.get("courseID")
        teacher_id = kwargs.get("teacherId")
        course_name = kwargs.get("courseName")
        course_description = kwargs.get("courseDescription")
        course_image_path = kwargs.get("courseImagePath")
        course_price = kwargs.get("coursePrice")
        course_category = kwargs.get("courseCategory")
        video_path = kwargs.get("videoPath")
        course_total_rating = 0
        course_rating_count = 0

        cur.execute(
            "INSERT INTO course VALUES (%(course_id)s, %(teacher_id)s, %(course_name)s, %(course_description)s, %(course_image_path)s, %(course_price)s, %(course_category)s, %(course_total_rating)s, %(course_rating_count)s, NOW(), %(video_path)s)",
            {"course_id":course_id, "teacher_id":teacher_id, "course_name":course_name, "course_description":course_description, "course_image_path":course_image_path, "course_price":course_price, "course_category":course_category, "course_total_rating":course_total_rating, "course_rating_count":course_rating_count, "video_path":video_path}
        )
        connection.commit()

    elif (mode == "get_course_data"):
        course_id = kwargs.get("courseID")
        print('Course_ID:', course_id)
        cur.execute("SELECT * FROM course WHERE course_id=%(course_id)s", {"course_id":course_id})
        matched = cur.fetchone()
        print('Matched:', matched)
        if (not matched):
            return False
        return matched

    # Added just in case want to do updating

    elif (mode == "update_course_title"):
        course_id = kwargs.get("courseID")
        course_title = kwargs.get("courseTitle")
        cur.execute("UPDATE course SET course_name=%(course_name)s WHERE course_id=%(courseID)s", {"course_name":course_title, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_description"):
        course_id = kwargs.get("courseID")
        course_description = kwargs.get("courseDescription")
        cur.execute("UPDATE course SET course_description=%(course_description)s WHERE course_id=%(courseID)s", {"course_description":course_description, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_category"):
        course_id = kwargs.get("courseID")
        course_category = kwargs.get("course_category")
        cur.execute("UPDATE course SET course_category=%(course_category)s WHERE course_id=%(courseID)s", {"course_category":course_category, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_price"):
        course_id = kwargs.get("courseID")
        course_price = kwargs.get("coursePrice")
        cur.execute("UPDATE course SET course_price=%(course_price)s WHERE course_id=%(courseID)s", {"course_price":course_price, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_thumbnail"):
        course_id = kwargs.get("courseID")
        course_image_path = kwargs.get("courseImagePath")
        cur.execute("UPDATE course SET course_image_path=%(course_image_path)s WHERE course_id=%(courseID)s", {"course_image_path":course_image_path, "courseID":course_id})
        connection.commit()

    elif (mode == "update_course_video"):
        course_id = kwargs.get("courseID")
        video_path = kwargs.get("videoPath")
        cur.execute("UPDATE course SET video_path=%(video_path)s WHERE course_id=%(courseID)s", {"video_path":video_path, "courseID":course_id})
        connection.commit()

    elif (mode == "delete"):
        course_id = kwargs.get("courseID")
        cur.execute("DELETE FROM course WHERE course_id=%(course_id)s", {"course_id":course_id})
        connection.commit()

    elif (mode == "get_3_latest_courses" or mode == "get_3_highly_rated_courses"):
        teacherID = kwargs.get("teacherID")
        # statement = "SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course "

        if (mode == "get_3_latest_courses"):
            # get the latest 3 courses
            if (not teacherID):
                cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course ORDER BY date_created DESC LIMIT 3")
            else:
                cur.execute("SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE teacher_id=%(teacherID)s ORDER BY date_created DESC LIMIT 3", {"teacherID":teacherID})
        else:
            # get top 3 highly rated courses
            if (not teacherID):
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
                    teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                                else (teacherProfile, False)
                    courseInfoList.append(Course(((teacherUsername, teacherProfile), matchedList[i])))
                return courseInfoList
            else:
                cur.execute("SELECT username, profile_image FROM user WHERE id=%(teacherID)s", {"teacherID":teacherID})
                res = cur.fetchone()
                teacherUsername = res[0]
                teacherProfile = res[1]
                teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                            else (teacherProfile, False)
                for tupleInfo in matchedList:
                    courseInfoList.append(Course(((teacherUsername, teacherProfile), tupleInfo)))

                if (kwargs.get("getTeacherUsername")):
                    return (courseInfoList, res[0])

                return courseInfoList

    elif (mode == "search"):
        searchInput = kwargs.get("searchInput")
        resultsList = []

        # cur.execute(f"SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE course_name LIKE '%{searchInput}%'")
        # foundResults = cur.fetchall()
        cur.execute("CALL search_for(%(searchInput)s)", {"searchInput":searchInput})
        foundResults = cur.fetchall()
        # cur.callproc("search_for", (searchInput,))
        # for result in cur.stored_results():
        #     foundResults = result.fetchall()

        teacherIDList = [teacherID[1] for teacherID in foundResults]
        for i, teacherID in enumerate(teacherIDList):
            cur.execute(f"SELECT username, profile_image FROM user WHERE id='{teacherID}'")
            res = cur.fetchone()
            teacherUsername = res[0]
            teacherProfile = res[1]
            teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                         else (teacherProfile, False)
            if ("googleusercontent" in teacherProfile[0]):
                teacherProfile = (res[1], True)

            resultsList.append(Course(((teacherUsername, teacherProfile), foundResults[i])))

        return resultsList

    else:
        connection.close()
        raise ValueError("Invalid mode in the session_sql_operation function!")

def review_sql_operation(connection:MySQLConnection=None, mode:str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the purchased table

    revieve keywords: userID, courseID,
    insert keywords: userID, courseID, courseRating, CourseReview

    """
    if mode is None:
        connection.close()
        raise ValueError("You must specify a mode in the review_sql_operation function!")

    cur = connection.cursor()

    userID = kwargs.get("userID")
    courseID = kwargs.get("courseID")

    if mode == "retrieve":
        cur.execute("SELECT course_rating FROM review WHERE user_id = %(userID)s AND course_id = %(courseID)s", {"userID":userID, "courseID":courseID})
        review_list = cur.fetchall()
        return review_list

    elif mode == "insert":
        courseRating = kwargs.get("courseRating")
        cur.execute("INSERT INTO review VALUES (%(userID)s, %(courseID)s, %(courseRating)s, %(courseReview)s)", {"userID":userID, "courseID":courseID, "courseRating":courseRating})
        connection.commit()

    else:
        connection.close()
        raise ValueError("Invalid mode in the review_sql_operation function!")
