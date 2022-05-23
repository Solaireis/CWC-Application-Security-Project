import uuid, sqlite3
from datetime import datetime
from __init__ import app

def generate_id():
    """
    Generates a unique ID
    """
    return uuid.uuid4().hex

def connect_to_database():
    """
    Connects to the database and returns the connection object
    """
    return sqlite3.connect(app.config["SQL_DATABASE"], timeout=5)

def user_sql_operation(mode=None, **kwargs):
    """
    Do CRUD operations on the user table
    
    Insert keywords: email, username, password
    Query keywords: email, password
    """
    if (not mode):
        raise ValueError("You must specify a mode in the user_sql_operation function!")

    con = connect_to_database()
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id PRIMARY KEY, 
        role TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE, 
        email TEXT NOT NULL UNIQUE, 
        password TEXT NOT NULL, 
        profile_image TEXT, 
        date_joined DATE NOT NULL,
        puchased_courses TEXT
    )""")
    returnValue = None
    if (mode == "insert"):
        emailInput = kwargs.get("email")
        usernameInput = kwargs.get("username")

        emailDupe = bool(cur.execute(f"SELECT * FROM user WHERE email='{emailInput}'").fetchall())

        usernameDupes = bool(cur.execute(f"SELECT * FROM user WHERE username='{usernameInput}'").fetchall())

        if (emailDupe or usernameDupes):
            con.close()
            returnValue = (emailDupe, usernameDupes)

        if (returnValue is None and not emailDupe and not usernameDupes):
            # add to the sqlite3 database
            userID = generate_id()
            passwordInput = kwargs.get("password")
            data = (userID, "Student", usernameInput, emailInput, passwordInput, None, datetime.now().strftime("%Y-%m-%d"), "[]")
            cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?, ?)", data)
            con.commit()
            returnValue = userID

    elif (mode == "login"):
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        cur.execute(f"SELECT id, role FROM user WHERE email='{emailInput}' AND password='{passwordInput}'")
        returnValue = cur.fetchall()
        if (not returnValue):
            returnValue = False
        else:
            returnValue = returnValue[0] # returnValue is a list of tuples.

    elif (mode == "get_user_data"):
        userID = kwargs.get("userID")
        cur.execute(f"SELECT * FROM user WHERE id='{userID}'")
        returnValue = cur.fetchall()
        if (not returnValue):
            returnValue = False
    
    elif (mode == "edit"):
        userID = kwargs.get("userID")
        usernameInput = kwargs.get("username")
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        statement = "UPDATE user SET "
        if (usernameInput):
            statement += f"username='{usernameInput}', "

        if (emailInput):
            statement += f"email='{emailInput}', "

        if (passwordInput):
            statement += f"password='{passwordInput}', "

        statement = statement[:-2] + f" WHERE id='{userID}'"
        cur.execute(statement)
        con.commit()

    elif (mode == "delete"):
        userID = kwargs.get("userID")
        cur.execute(f"DELETE FROM user WHERE id='{userID}'")
        con.commit()

    con.close()
    return returnValue

def course_sql_operation(mode=None, **kwargs):
    if (not mode):
        raise ValueError("You must specify a mode in the course_sql_operation function!")

    con = connect_to_database()
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS course (
        course_id PRIMARY KEY, 
        teacher_id TEXT NOT NULL,
        course_name TEXT NOT NULL,
        course_description TEXT,
        course_image_path TEXT,
        course_price TEXT,
        course_total_rating INT,
        course_rating_count INT,
        date_uploaded DATE NOT NULL
    )""")
    if (mode == "insert"):
        course_id = generate_id()
        teacher_id = kwargs.get("teacher_id")
        course_name = kwargs.get("course_name")
        course_description = kwargs.get("course_description")
        course_image_path = kwargs.get("course_image_path")
        course_price = kwargs.get("course_price")
        course_total_rating = 0
        course_rating_count = 0
        date_uploaded = datetime.now().strftime("%Y-%m-%d")
        
        data = (course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_total_rating, course_rating_count, date_uploaded)
        cur.execute("INSERT INTO course VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
        con.commit()

    elif (mode == "query"):
        course_id = kwargs.get("course_id")
        cur.execute(f"SELECT * FROM course WHERE course_id='{course_id}'")
        returnValue = cur.fetchall()
        if (not returnValue):
            returnValue = False
    
    elif (mode == "edit"):
        course_id = kwargs.get("course_id")
        course_name = kwargs.get("course_name")
        course_description = kwargs.get("course_description")
        course_image_path = kwargs.get("course_image_path")
        course_price = kwargs.get("course_price")
        cur.execute(f"UPDATE course SET course_name='{course_name}', course_description='{course_description}', course_image_path='{course_image_path}', course_price='{course_price}' WHERE course_id='{course_id}'")
        con.commit()
    
    elif (mode == "delete"):
        course_id = kwargs.get("course_id")
        cur.execute(f"DELETE FROM course WHERE course_id='{course_id}'")
        con.commit()
        
    con.close()
    return