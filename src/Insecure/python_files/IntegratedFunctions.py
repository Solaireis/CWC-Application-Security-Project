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
    con = connect_to_database()
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id PRIMARY KEY, 
        role TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE, 
        email TEXT NOT NULL UNIQUE, 
        password TEXT NOT NULL, 
        profile_image TEXT NOT NULL, 
        date_joined DATE NOT NULL
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
            data = (userID, "Student", usernameInput, emailInput, passwordInput, "/static/images/user/default.jpg", datetime.now().strftime("%Y-%m-%d"))
            cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?)", data)
            con.commit()
            returnValue = userID

    elif (mode == "login"):
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        cur.execute(f"SELECT id, role FROM user WHERE email='{emailInput}' AND password='{passwordInput}'")
        returnValue = cur.fetchall()
        if (not returnValue):  # An empty list evaluates to False.
            returnValue = False
        #No else statement if no results will incur a type error so im assuming its not there to display insecure
        returnValue = returnValue[0] # returnValue is a list of tuples.

    elif (mode == "get_user_data"):
        userID = kwargs.get("userID")
        cur.execute(f"SELECT * FROM user WHERE id='{userID}'")
        returnValue = cur.fetchall()
        if (not returnValue):  # An empty list evaluates to False.
            returnValue = False

    con.close()
    return returnValue