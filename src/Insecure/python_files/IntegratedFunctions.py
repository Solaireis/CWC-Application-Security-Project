import uuid, sqlite3, json
from datetime import datetime
from __init__ import app
from dicebear import DAvatar, DStyle
from .Course import Course

def generate_id():
    """
    Generates a unique ID
    """
    return uuid.uuid4().hex

def get_image_path(userID, returnUserInfo=False):
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

def get_dicebear_image(username):
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

def sql_operation(table=None, mode=None, **kwargs):
    """
    Connects to the database and returns the connection object
    
    Args:
        - table: The table to connect to ("course", "user")
        - mode: The mode to use ("insert", "edit", "login", etc.)
        - kwargs: The keywords to pass into the respective sql operation functions
    
    Returns the returned value from the SQL operation.
    """
    returnValue = None
    # timeout is in seconds to give time to other threads that is connected to the SQL database.
    # After the timeout, an OperationalError will be raised, stating "database is locked".
    con = sqlite3.connect(app.config["SQL_DATABASE"], timeout=10)
    if (table == "user"):
        returnValue = user_sql_operation(connection=con, mode=mode, **kwargs)
    elif (table == "course"):
        returnValue = course_sql_operation(connection=con, mode=mode, **kwargs)

    con.close()
    return returnValue

def user_sql_operation(connection=None, mode=None, **kwargs):
    """
    Do CRUD operations on the user table
    
    insert keywords: email, username, password
    login keywords: email, password
    get_user_data keywords: userID
    edit keywords: userID, username, password, email, profileImagePath
    delete keywords: userID
    """
    if (not mode):
        raise ValueError("You must specify a mode in the user_sql_operation function!")

    cur = connection.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id PRIMARY KEY, 
        role TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE, 
        email TEXT NOT NULL UNIQUE, 
        password TEXT NOT NULL, 
        profile_image TEXT, 
        date_joined DATE NOT NULL,
        puchased_courses TEXT NOT NULL
    )""")
    if (mode == "verify_userID_existence"):
        userID = kwargs.get("userID")
        if (not userID):
            raise ValueError("You must specify a userID in the user_sql_operation function when verifying userID!")
        cur.execute("SELECT * FROM user WHERE id=?", (userID,))
        return bool(cur.fetchone())

    elif (mode == "insert"):
        emailInput = kwargs.get("email")
        usernameInput = kwargs.get("username")

        emailDupe = bool(cur.execute(f"SELECT * FROM user WHERE email='{emailInput}'").fetchall())

        usernameDupes = bool(cur.execute(f"SELECT * FROM user WHERE username='{usernameInput}'").fetchall())

        if (emailDupe or usernameDupes):
            return (emailDupe, usernameDupes)

        # add to the sqlite3 database
        userID = generate_id()
        passwordInput = kwargs.get("password")
        data = (userID, "Student", usernameInput, emailInput, passwordInput, None, datetime.now().strftime("%Y-%m-%d"), "{}")
        cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?, ?)", data)
        connection.commit()
        return userID

    elif (mode == "login"):
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        cur.execute(f"SELECT id, role FROM user WHERE email='{emailInput}' AND password='{passwordInput}'")
        matched = cur.fetchone()
        if (not matched):
            return False
        return matched

    elif (mode == "get_user_data"):
        userID = kwargs.get("userID")
        cur.execute(f"SELECT * FROM user WHERE id='{userID}'")
        matched = cur.fetchone()
        if (not matched):
            return False
        return matched

    elif (mode == "edit"):
        userID = kwargs.get("userID")
        usernameInput = kwargs.get("username")
        emailInput = kwargs.get("email")
        oldPasswordInput = kwargs.get("oldPassword")
        passwordInput = kwargs.get("password")
        profileImagePath = kwargs.get("profileImagePath")
        newAccType = kwargs.get("newAccType")
        statement = "UPDATE user SET "
        if (usernameInput is not None):
            duplicates = (f"SELECT * FROM user WHERE username='{usernameInput}'")
            cur.execute(duplicates)
            matched = cur.fetchone()
            if (not matched):
                statement += f"username='{usernameInput}'"
            else:
                return False

        if (emailInput is not None):
            duplicates = (f"SELECT * FROM user WHERE email='{emailInput}'")
            cur.execute(duplicates)
            matched = cur.fetchone()
            if (not matched):
                statement += f"email='{emailInput}'"
            else:
                return False

        if (passwordInput is not None):
            duplicates = (f"SELECT password FROM user WHERE id='{userID}'")
            cur.execute(duplicates)
            userPassword = cur.fetchone()[0]
            if (userPassword == oldPasswordInput):
                if (userPassword != passwordInput):
                    statement += f"password='{passwordInput}'"
                else:
                    return "Cannot Reuse previous password!"
            else:
                return "Password does not match previous password!"

        if (profileImagePath is not None):
            statement += f"profile_image='{profileImagePath}'"

        if (newAccType is not False):
            statement += "role='Teacher'"

        statement += f" WHERE id='{userID}'"
        print(statement)
        cur.execute(statement)
        connection.commit()

    elif (mode == "delete"):
        userID = kwargs.get("userID")
        cur.execute(f"DELETE FROM user WHERE id='{userID}'")
        connection.commit()

    elif (mode == "get_user_purchases"):
        userID = kwargs.get("userID")
        cur.execute(f"SELECT puchased_courses FROM user WHERE id='{userID}'")
        return json.loads(cur.fetchone()[0])

def course_sql_operation(connection=None, mode=None, **kwargs):
    """
    Do CRUD operations on the course table
    
    insert keywords: teacherID
    
    get_course_data keywords: courseID

    edit keywords: 
    """
    if (not mode):
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
        course_id = kwargs.get("courseId")
        cur.execute(f"SELECT * FROM course WHERE course_id='{course_id}'")
        matched = cur.fetchone()
        if (not matched):
            return False
        return matched

    elif (mode == "edit"):
        course_id = kwargs.get("courseId")
        course_name = kwargs.get("courseName")
        course_description = kwargs.get("courseDescription")
        course_image_path = kwargs.get("courseImagePath")
        course_price = kwargs.get("coursePrice")
        course_category = kwargs.get("courseCategory")
        course_total_rating = kwargs.get("courseTotalRating")
        course_rating_count = kwargs.get("courseRatingCount")

    elif (mode == "delete"):
        course_id = kwargs.get("courseId")
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
                    cur.execute(f"SELECT username, profile_image FROM user WHERE id='{teacherID}'")
                    courseInfoList.append(Course((cur.fetchone(), matchedList[i])))
                return courseInfoList
            else:
                teacherInfo = cur.execute(f"SELECT username, profile_image FROM user WHERE id='{teacherID}'").fetchone()

                for tupleInfo in matchedList:
                    courseInfoList.append(Course((teacherInfo, tupleInfo)))
                
                if (kwargs.get("getTeacherUsername")):
                    return (courseInfoList, teacherInfo[0])

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

