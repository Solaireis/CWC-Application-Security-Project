"""
This python file contains all the functions that requires the import of the
flask web application's app variable from __init__.py.
"""

# import Flask web application configs
from __init__ import app
from flask import url_for

# import python standard libraries
import sqlite3, json
from datetime import datetime, timedelta
from typing import Union
from time import sleep
import mysql.connector
import os

# import third party libraries
from dicebear import DAvatar, DStyle
from argon2 import PasswordHasher as PH
from argon2.exceptions import VerifyMismatchError

# for google oauth login
from google_auth_oauthlib.flow import Flow

# import local python files
from .Course import Course
from .Errors import *
from .NormalFunctions import generate_id, pwd_has_been_pwned, pwd_is_strong
from .Google import CREDENTIALS_PATH

"""------------------------------ Define Constants ------------------------------"""

MAX_LOGIN_ATTEMPTS = 10

"""------------------------------ End of Defining Constants ------------------------------"""

def get_google_flow() -> Flow:
    """
    Returns the Google OAuth2 flow.
    """
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_PATH,
        ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"], redirect_uri=url_for("loginCallback", _external=True)
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
    """
    userInfo = sql_operation(table="user", mode="get_user_data", userID=userID)
    imageSrcPath = userInfo[5]
    if (not imageSrcPath):
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

    try:
        con = mysql.connector.connect(
            host="localhost",
            user="root",
            password=os.environ['SQL_PASS'],
            database= "appsecdatabase",
        )

    except (mysql.connector.errors.ProgrammingError):
        print("Database Not Found. Please create one first")

    try:
        if (table == "user"):
            returnValue = user_sql_operation(connection=con, mode=mode, **kwargs)
        elif (table == "course"):
            returnValue = course_sql_operation(connection=con, mode=mode, **kwargs)
        # elif table == "cart":
        #     returnValue = cart_sql_operation(connection=con, mode=mode, **kwargs)
        # elif table == "purchased":
        #     returnValue = purchased_sql_operation(connection=con, mode=mode, **kwargs)
        elif (table == "session"):
            returnValue = session_sql_operation(connection=con, mode=mode, **kwargs)
        elif (table == "login_attempts"):
            returnValue = login_attempts_sql_operation(connection=con, mode=mode, **kwargs)
        elif (table == "2fa_token"):
            returnValue = twofa_token_sql_operation(connection=con, mode=mode, **kwargs)
    except (mysql.connector.Error) as e:
        # to ensure that the connection is closed even if an error with sqlite3 occurs
        print("Error caught:")
        print(e)

    con.close()
    return returnValue

def twofa_token_sql_operation(connection:mysql.connector.connection.MySQLConnection, mode:str=None, **kwargs) -> Union[bool, str, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the twofa_token_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS twofa_token (
        token PRIMARY KEY,
        user_id TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")
    connection.commit()

    if (mode == "add_token"):
        token = kwargs.get("token")
        userID = kwargs.get("userID")

        cur.execute("INSERT INTO twofa_token (token, user_id) VALUES (?, ?)", (token, userID))
        connection.commit()

    elif (mode == "get_token"):
        userID = kwargs.get("userID")
        cur.execute("SELECT token FROM twofa_token WHERE user_id = ?", (userID,))
        matchedToken = cur.fetchone()
        if (matchedToken is None):
            connection.close()
            raise No2FATokenError("No 2FA OTP found for this user!")

        return matchedToken[0]

    elif (mode == "check_if_user_has_2fa"):
        userID = kwargs.get("userID")
        cur.execute("SELECT token FROM twofa_token WHERE user_id = ?", (userID,))
        matchedToken = cur.fetchone()
        return True if (matchedToken is not None) else False

    elif (mode == "delete_token"):
        userID = kwargs.get("userID")
        cur.execute("DELETE FROM twofa_token WHERE user_id = ?", (userID,))
        connection.commit()

def login_attempts_sql_operation(connection:mysql.connector.connection.MySQLConnection, mode:str=None, **kwargs) -> None:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the login_attempts_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        user_id PRIMARY KEY,
        attempts INT NOT NULL,
        reset_date DATE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")
    connection.commit()

    if (mode == "add_attempt"):
        emailInput = kwargs.get("email")
        userID = cur.execute("SELECT id FROM user WHERE email = ?", (emailInput,)).fetchone()
        if (userID is None):
            connection.close()
            raise EmailDoesNotExistError("Email does not exist!")

        userID = userID[0]
        cur.execute("SELECT attempts, reset_date FROM login_attempts WHERE user_id = ?", (userID,))
        attempts = cur.fetchone()
        if (attempts is None):
            cur.execute("INSERT INTO login_attempts (user_id, attempts, reset_date) VALUES (?, ?, ?)", (userID, 1, datetime.now() + timedelta(minutes=app.config["LOCKED_ACCOUNT_DURATION"])))
        else:
            # comparing the reset datetime with the current datetime
            if (datetime.strptime(attempts[1], "%Y-%m-%d %H:%M:%S.%f") > datetime.now()):
                # if not past the reset datetime
                currentAttempts = attempts[0]
            else:
                # if past the reset datetime, reset the attempts to 0
                currentAttempts = 0

            if (currentAttempts > MAX_LOGIN_ATTEMPTS):
                # if reached max attempts per account
                connection.close()
                raise AccountLockedError("User have exceeded the maximum number of password attempts!")

            cur.execute("UPDATE login_attempts SET attempts = ?, reset_date = ? WHERE user_id = ?", (currentAttempts + 1, datetime.now() + timedelta(minutes=app.config["LOCKED_ACCOUNT_DURATION"]), userID))
        connection.commit()

    elif (mode == "reset_user_attempts"):
        userID = kwargs.get("userID")
        cur.execute("DELETE FROM login_attempts WHERE user_id = ?", (userID,))
        connection.commit()

    elif (mode == "reset_attempts_past_reset_date"):
        cur.execute("DELETE FROM login_attempts WHERE reset_date < ?", (datetime.now(),))
        connection.commit()

def session_sql_operation(connection:mysql.connector.connection.MySQLConnection, mode:str=None, **kwargs) -> Union[str, bool, None]:
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the session_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS session (
        session_id PRIMARY KEY,
        user_id TEXT NOT NULL,
        expiry_date DATE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")
    connection.commit()

    if (mode == "create_session"):
        sessionID = kwargs.get("sessionID")
        userID = kwargs.get("userID")
        expiryDate = datetime.now() + timedelta(minutes=app.config["SESSION_EXPIRY_INTERVALS"])
        cur.execute("INSERT INTO session VALUES (?, ?, ?)", (sessionID, userID, expiryDate))
        connection.commit()

    elif (mode == "get_user_id"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT user_id FROM session WHERE session_id = ?", (sessionID,))
        userID = cur.fetchone()[0]
        return userID

    elif (mode == "get_session"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT * FROM session WHERE session_id = ?", (sessionID,))
        returnValue = cur.fetchone()
        return returnValue

    elif (mode == "delete_session"):
        sessionID = kwargs.get("sessionID")
        cur.execute("DELETE FROM session WHERE session_id = ?", (sessionID,))
        connection.commit()

    elif (mode == "update_session"):
        sessionID = kwargs.get("sessionID")
        expiryDate = datetime.now() + timedelta(minutes=app.config["SESSION_EXPIRY_INTERVALS"])
        cur.execute("UPDATE session SET expiry_date = ? WHERE session_id = ?", (expiryDate, sessionID))
        connection.commit()

    elif (mode == "check_if_valid"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT user_id, expiry_date FROM session WHERE session_id = ?", (sessionID,))
        result = cur.fetchone()
        expiryDate = datetime.strptime(result[1], "%Y-%m-%d %H:%M:%S.%f")
        if (expiryDate >= datetime.now()):
            # not expired, check if the userID matches the sessionID
            return kwargs.get("userID") == result[0]
        else:
            # expired
            return False

    elif (mode == "delete_expired_sessions"):
        cur.execute("DELETE FROM session WHERE expiry_date < ?", (datetime.now(),))
        connection.commit()

    elif (mode == "if_session_exists"):
        sessionID = kwargs.get("sessionID")
        cur.execute("SELECT * FROM session WHERE session_id = ?", (sessionID,))
        returnValue = cur.fetchone()
        if (returnValue):
            return True
        else:
            return False

    elif (mode == "delete_users_other_session"):
        # delete all session of a user except the current session id
        userID = kwargs.get("userID")
        sessionID = kwargs.get("sessionID")
        cur.execute("DELETE FROM session WHERE user_id = ? AND session_id != ?", (userID, sessionID))
        connection.commit()

def user_sql_operation(connection:mysql.connector.connection.MySQLConnection, mode:str=None, **kwargs) -> Union[str, tuple, bool, dict, None]:
    """
    Do CRUD operations on the user table
    
    insert keywords: email, username, password
    login keywords: email, password
    get_user_data keywords: userID
    add_to_cart keywords: userID, courseID
    remove_from_cart keywords: userID, courseID
    purchase_courses keywords: userID
    delete keywords: userID
    """
    if (mode is None):
        connection.close()
        raise ValueError("You must specify a mode in the user_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id VARCHAR(255) PRIMARY KEY, 
        role VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL UNIQUE, 
        email VARCHAR(255) NOT NULL UNIQUE, 
        password VARCHAR(255), -- can be null for user who signed in using Google OAuth2
        profile_image VARCHAR(255), 
        date_joined DATE NOT NULL,
        card_name VARCHAR(255),
        card_no INTEGER, -- May not be unique since one might have alt accounts.
        card_exp VARCHAR(255),
        cart_courses VARCHAR(255) NOT NULL,
        purchased_courses VARCHAR(255) NOT NULL
    )""")

    """Honestly IDK wether need a not"""
    connection.commit()

    if (mode == "verify_userID_existence"):
        userID = kwargs.get("userID")
        if (not userID):
            connection.close()
            raise ValueError("You must specify a userID when verifying the userID!")
        cur.execute("SELECT * FROM user WHERE id=?", (userID,))
        return bool(cur.fetchone())

    # elif (mode == "get_username"):
    #     userID = kwargs.get("userID")
    #     cur.execute("SELECT username FROM user WHERE id=?", (userID,))
    #     username = cur.fetchone()
    #     return username[0] if (username is not None) else None

    elif (mode == "signup"):
        emailInput = kwargs.get("email")
        usernameInput = kwargs.get("username")

        emailDupe = bool(cur.execute(f"SELECT * FROM user WHERE email='{emailInput}'").fetchone())
        usernameDupes = bool(cur.execute(f"SELECT * FROM user WHERE username='{usernameInput}'").fetchone())

        if (emailDupe or usernameDupes):
            return (emailDupe, usernameDupes)

        # add to the sqlite3 database
        userID = generate_id()
        passwordInput = kwargs.get("password")
        data = (userID, "Student", usernameInput, emailInput, passwordInput, None, datetime.now().strftime("%Y-%m-%d"), None, None, None, "[]", "[]")
        cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
        connection.commit()
        return userID

    elif (mode == "check_if_using_google_oauth2"):
        userID = kwargs.get("userID")
        cur.execute("SELECT password FROM user WHERE id=?", (userID,))
        password = cur.fetchone()
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

        # check if the userID exists
        cur.execute("SELECT role FROM user WHERE id=?", (userID,))
        matched = cur.fetchone()
        if (matched is None):
            data = (userID, "Student", username, email, None, googleProfilePic, datetime.now().strftime("%Y-%m-%d"), None, None, None, "[]", "[]")
            cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
            connection.commit()
            return "Student"
        else:
            # return the role of the user
            return matched[0]

    elif (mode == "login"):
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        cur.execute(f"SELECT id, role, password FROM user WHERE email='{emailInput}'")
        matched = cur.fetchone()
        if (not matched):
            connection.close()
            raise EmailDoesNotExistError("Email does not exist!")

        lockedAccount = cur.execute("SELECT attempts FROM login_attempts WHERE user_id=?", (matched[0],)).fetchone()
        if (lockedAccount):
            if (lockedAccount[0] > MAX_LOGIN_ATTEMPTS):
                connection.close()
                raise AccountLockedError("Account is locked!")
            else:
                # reset the attempts
                cur.execute("DELETE FROM login_attempts WHERE user_id=?", (matched[0],))
                connection.commit()

        try:
            if (PH().verify(matched[2], passwordInput)):
                return (matched[0], matched[1])
        except (VerifyMismatchError):
            connection.close()
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "get_user_data"):
        userID = kwargs.get("userID")
        cur.execute(f"SELECT * FROM user WHERE id='{userID}'")
        matched = cur.fetchone()
        if (not matched):
            return False
        return matched

    elif (mode == "change_username"):
        userID = kwargs.get("userID")
        usernameInput = kwargs.get("username")
        reusedUsername = bool(cur.execute(f"SELECT * FROM user WHERE username='{usernameInput}'").fetchone())

        if (reusedUsername):
            connection.close()
            raise ReusedUsernameError(f"The username {usernameInput} is already in use!")

        cur.execute(f"UPDATE user SET username='{usernameInput}' WHERE id='{userID}'")
        connection.commit()

    elif (mode == "change_email"):
        userID = kwargs.get("userID")
        currentPasswordInput = kwargs.get("currentPassword")
        emailInput = kwargs.get("email")

        reusedEmail = cur.execute(f"SELECT id, password FROM user WHERE email='{emailInput}'").fetchone()
        if (reusedEmail is not None):
            if (reusedEmail[0] == userID):
                connection.close()
                raise SameAsOldEmailError(f"The email {emailInput} is the same as the old email!")
            else:
                connection.close()
                raise EmailAlreadyInUseError(f"The email {emailInput} is already in use!")

        currentPassword = cur.execute(f"SELECT password FROM user WHERE id='{userID}'").fetchone()
        try:
            if (PH().verify(currentPassword[0], currentPasswordInput)):
                cur.execute(f"UPDATE user SET email='{emailInput}' WHERE id='{userID}'")
                connection.commit()
        except (VerifyMismatchError):
            connection.close()
            raise IncorrectPwdError("Incorrect password!")

    elif (mode == "change_password"):
        userID = kwargs.get("userID")
        oldPasswordInput = kwargs.get("oldPassword") # to authenticate the changes
        passwordInput = kwargs.get("password")
        currentPasswordHash = cur.execute(f"SELECT password FROM user WHERE id='{userID}'").fetchone()[0]

        try:
            # check if the supplied old password matches the current password
            if (PH().verify(currentPasswordHash, oldPasswordInput)):
                if (len(passwordInput) < 10):
                    connection.close()
                    raise PwdTooShortError("The password must be at least 10 characters long!")

                if (len(passwordInput) > 48):
                    connection.close()
                    raise PwdTooLongError("The password must be less than 48 characters long!")

                if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
                    connection.close()
                    raise PwdTooWeakError("The password is too weak!")

                cur.execute(f"UPDATE user SET password='{PH().hash(passwordInput)}' WHERE id='{userID}'")
                connection.commit()
        except (VerifyMismatchError):
            connection.close()
            raise ChangePwdError("The old password is incorrect!")

    elif (mode == "check_card_if_exist"):
        userID = kwargs.get("userID")
        getCardInfo = kwargs.get("getCardInfo")

        cur.execute(f"SELECT card_name, card_no, card_exp FROM user WHERE id='{userID}'")
        cardInfo = cur.fetchone()
        if (cardInfo is None):
            connection.close()
            raise CardDoesNotExistError("Credit card does not exist!")

        for info in cardInfo:
            if (info is None):
                # if any information is missing which should not be possible, 
                # the card will then be considered to not exist and will reset the card info to Null
                cur.execute(f"UPDATE user SET card_name=NULL, card_no=NULL, card_exp=NULL WHERE id='{userID}'")
                connection.commit()
                raise CardDoesNotExistError("Credit card is missing some information!")

        if (getCardInfo):
            return cardInfo

    elif (mode == "add_card"):
        userID = kwargs.get("userID")
        cardName = kwargs.get("cardName")
        cardNo = kwargs.get("cardNo")
        cardExp = kwargs.get("cardExpiry")

        cur.execute(f"UPDATE user SET card_name='{cardName}', card_no={cardNo}, card_exp='{cardExp}' WHERE id='{userID}'")
        connection.commit()

    elif (mode == "delete_card"):
        userID = kwargs.get("userID")
        cur.execute(f"UPDATE user SET card_name=NULL, card_no=NULL, card_exp=NULL WHERE id='{userID}'")
        connection.commit()

    elif (mode == "update_card"):
        userID = kwargs.get("userID")
        cardExp = kwargs.get("cardExpiry")
        cardCvv = kwargs.get("cardCVV")
        cur.execute(f"UPDATE user SET card_exp='{cardExp}' WHERE id='{userID}'")
        connection.commit()

    elif (mode == "delete_user"):
        userID = kwargs.get("userID")
        cur.execute(f"DELETE FROM user WHERE id='{userID}'")
        connection.commit()

    elif (mode == "update_to_teacher"):
        userID = kwargs.get("userID")

        currentRole = cur.execute(f"SELECT role FROM user WHERE id='{userID}'").fetchone()
        isTeacher = False
        if (currentRole):
            isTeacher = True if (currentRole[0] == "Teacher") else False

        if (not isTeacher):
            cur.execute(f"UPDATE user SET role='Teacher' WHERE id='{userID}'")
            connection.commit()
        else:
            connection.close()
            raise IsAlreadyTeacherError("The user is already a teacher!")

    elif (mode == "get_user_purchases"):
        userID = kwargs.get("userID")
        cur.execute(f"SELECT purchased_courses FROM user WHERE id='{userID}'")
        return json.loads(cur.fetchone()[0])

    elif mode == "get_user_cart":
        userID = kwargs.get("userID")
        cur.execute(f"SELECT cart_courses FROM user WHERE id='{userID}'")
        return json.loads(cur.fetchone()[0])

    elif mode == "add_to_cart":
        userID = kwargs.get("userID")
        courseID = kwargs.get("courseID")

        cur.execute(f"SELECT cart_courses FROM user WHERE id='{userID}'")
        cartCourseIDs = json.loads(cur.fetchone()[0])

        cur.execute(f"SELECT purchased_courses FROM user WHERE id='{userID}'")
        purchasedCourseIDs = json.loads(cur.fetchone()[0])
        
        if courseID not in cartCourseIDs and courseID not in purchasedCourseIDs:
            cartCourseIDs.append(courseID)
            cur.execute(f"UPDATE user SET cart_courses='{json.dumps(cartCourseIDs)}' WHERE id='{userID}'")
            connection.commit()

    elif mode == "remove_from_cart":
        userID = kwargs.get("userID")
        courseID = kwargs.get("courseID")

        cur.execute(f"SELECT cart_courses FROM user WHERE id='{userID}'")
        cartCourseIDs = json.loads(cur.fetchone()[0])

        if courseID in cartCourseIDs:
            cartCourseIDs.remove(courseID)
            cur.execute(f"UPDATE user SET cart_courses='{json.dumps(cartCourseIDs)}' WHERE id='{userID}'")
            connection.commit()

    elif mode == "purchase_courses":

        userID = kwargs.get("userID")

        cur.execute(f"SELECT cart_courses FROM user WHERE id='{userID}'")
        cartCourseIDs = json.loads(cur.fetchone()[0])

        cur.execute(f"SELECT purchased_courses FROM user WHERE id='{userID}'")
        purchasedCourseIDs = json.loads(cur.fetchone()[0])

        for courseID in cartCourseIDs:
        
            if courseID not in purchasedCourseIDs:
                purchasedCourseIDs.append(courseID)
        
        # Add to purchases
        cur.execute(f"UPDATE user SET purchased_courses='{json.dumps(purchasedCourseIDs)}' WHERE id='{userID}'")        
        
        # Empty cart
        cur.execute(f"UPDATE user SET cart_courses='[]' WHERE id='{userID}'")

        connection.commit()

# May not be used
def course_sql_operation(connection:mysql.connector.connection.MySQLConnection=None, mode:str=None, **kwargs)  -> Union[list, tuple, bool, None]:
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
    cur.execute("""CREATE TABLE IF NOT EXISTS course (
        course_id PRIMARY KEY, 
        teacher_id TEXT NOT NULL,
        course_name TEXT NOT NULL,
        course_description TEXT,
        course_image_path TEXT,
        course_price FLOAT NOT NULL,
        course_category TEXT NOT NULL,
        course_total_rating INT NOT NULL,
        course_rating_count INT NOT NULL,
        date_created DATE NOT NULL,
        video_path TEXT NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")
    connection.commit()

    if (mode == "insert"):
        course_id = generate_id()
        teacher_id = kwargs.get("teacherId")
        course_name = kwargs.get("courseName")
        course_description = kwargs.get("courseDescription")
        course_image_path = kwargs.get("courseImagePath")
        course_price = kwargs.get("coursePrice")
        course_category = kwargs.get("courseCategory")
        video_path = kwargs.get("videoPath")
        course_total_rating = 0
        course_rating_count = 0
        date_created = datetime.now().strftime("%Y-%m-%d")
        
        data = (course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, course_total_rating, course_rating_count, date_created, video_path)
        cur.execute("INSERT INTO course VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
        connection.commit()

    elif (mode == "get_course_data"):
        course_id = kwargs.get("courseID")
        print(course_id)
        cur.execute(f"SELECT * FROM course WHERE course_id='{course_id}'")
        matched = cur.fetchone()
        print(matched)
        if (not matched):
            return False
        return matched

    elif (mode == "delete"):
        course_id = kwargs.get("courseID")
        cur.execute(f"DELETE FROM course WHERE course_id='{course_id}'")
        connection.commit()

    elif (mode == "get_3_latest_courses" or mode == "get_3_highly_rated_courses"):
        teacherID = kwargs.get("teacherID")
        statement = "SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course "

        if (mode == "get_3_latest_courses"):
            # get the latest 3 courses
            if (not teacherID):
                cur.execute(f"{statement} ORDER BY ROWID DESC LIMIT 3")
            else:
                cur.execute(f"{statement} WHERE teacher_id='{teacherID}' ORDER BY ROWID DESC LIMIT 3")
        else:
            # get top 3 highly rated courses
            if (not teacherID):
                cur.execute(f"{statement} ORDER BY (course_total_rating/course_rating_count) DESC LIMIT 3")
            else:
                cur.execute(f"{statement} WHERE teacher_id='{teacherID}' ORDER BY (course_total_rating/course_rating_count) DESC LIMIT 3")

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
                    res = cur.execute(f"SELECT username, profile_image FROM user WHERE id='{teacherID}'").fetchone()
                    teacherUsername = res[0]
                    teacherProfile = res[1]
                    teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                                else (teacherProfile, False)
                    courseInfoList.append(Course(((teacherUsername, teacherProfile), matchedList[i])))
                return courseInfoList
            else:
                res = cur.execute(f"SELECT username, profile_image FROM user WHERE id='{teacherID}'").fetchone()
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

        foundResults = cur.execute(f"SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE course_name LIKE '%{searchInput}%'").fetchall()
        teacherIDList = [teacherID[1] for teacherID in foundResults]
        for i, teacherID in enumerate(teacherIDList):
            res = cur.execute(f"SELECT username, profile_image FROM user WHERE id='{teacherID}'").fetchone()
            teacherUsername = res[0]
            teacherProfile = res[1]
            teacherProfile = (get_dicebear_image(teacherUsername), True) if (not teacherProfile) \
                                                                         else (teacherProfile, False)
            resultsList.append(Course(((teacherUsername, teacherProfile), foundResults[i])))

        return resultsList

# May not be used
def cart_sql_operation(connection:mysql.connector.connection.MySQLConnection=None, mode:str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the cart table
    
    insert keywords: userID, courseID
    get_cart_data keywords: userID
    remove keywords: userID, courseID
    empty keywords: userID
    """

    if mode is None:
        connection.close()
        raise ValueError("You must specify a mode in the cart_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS cart (
        user_id TEXT,
        course_id TEXT,
        PRIMARY KEY (user_id, course_id)
    )""")

    userID = kwargs.get("userID")

    if mode == "insert":
        courseID = kwargs.get("courseID")
        cur.execute("INSERT INTO cart VALUES (?, ?)", (userID, courseID))
        connection.commit()

    elif mode == "get_cart_courses":
        # List of course IDs in cart
        courseID_list = cur.execute(f"SELECT course_id FROM cart WHERE user_id = '{userID}'").fetchall()
        return courseID_list

    elif mode == "remove":
        courseID = kwargs.get("courseID")
        cur.execute("DELETE FROM cart WHERE user_id = '{userID}' AND course_id = '{courseID}'")
        connection.commit()

    elif mode == "empty":
        cur.execute("DELETE FROM cart WHERE user_id = '{userID}'")
        connection.commit()
    
# May not be used
def purchased_sql_operation(connection:mysql.connector.connection.MySQLConnection=None, mode:str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the purchased table
    
    insert keywords: userID, courseID
    get_purchased_data keywords: userID
    delete keywords: userID, courseID
    """

    if mode is None:
        connection.close()
        raise ValueError("You must specify a mode in the purchased_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS purchased (
        user_id TEXT,
        course_id TEXT,
        PRIMARY KEY (user_id, course_id)
    )""")

    userID = kwargs.get("userID")

    if mode == "insert":
        courseID = kwargs.get("courseID")
        cur.execute("INSERT INTO purchased VALUES (?, ?)", (userID, courseID))
        connection.commit()

    elif mode == "get_purchased_courses":
        # List of course IDs in purchased
        courseID_list = cur.execute(f"SELECT course_id FROM purchased WHERE user_id = '{userID}'").fetchall()
        return courseID_list

    elif mode == "delete":
        courseID = kwargs.get("courseID")
        cur.execute("DELETE FROM purchased WHERE user_id = '{userID}' AND course_id = '{courseID}'")
        connection.commit()

def review_sql_operation(connection:mysql.connector.connection.MySQLConnection=None, mode: str=None, **kwargs) -> Union[list, None]:
    """
    Do CRUD operations on the purchased table

    revieve keywords: userID, courseID, 
    insert keywords: userID, courseID, courseRating, CourseReview
    
    """
    if mode is None:
        connection.close()
        raise ValueError("You must specify a mode in the review_sql_operation function!")
    
    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id TEXT,
        course_id TEXT,
        course_rating INTEGER,
        course_review TEXT,
        
        PRIMARY KEY (user_id, course_id)
    )""")

    userID = kwargs.get("userID")
    courseID = kwargs.get("courseID")

    if mode == "retrieve":
        review_list = cur.execute(f"SELECT course_rating, course_review FROM review WHERE user_id = '{userID}' AND course_id = '{courseID}'").fetchall()
        return review_list

    if mode == "insert":
        courseRating = kwargs.get("courseRating")
        courseReview = kwargs.get("courseReview")
        cur.execute("INSERT INTO review VALUES (?, ?, ?, ?)", (userID, courseID, courseRating, courseReview))
        connection.commit()