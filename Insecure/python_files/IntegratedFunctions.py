import uuid, sqlite3
from datetime import datetime
from __init__ import app

def generate_id():
    """
    Generates a unique ID
    """
    return uuid.uuid4().hex

def user_sql_operation(mode=None, **kwargs):
    """
    Do CRUD operations on the user table
    
    Insert keywords: email, username, password
    Query keywords: email, password
    """
    con = sqlite3.connect(app.config["USER_DATABASE_SQL"], timeout=5)
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
            data = (userID, "student", usernameInput, emailInput, passwordInput, "/static/images/user/default.jpg", datetime.now().strftime("%Y-%m-%d"))
            cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?)", data)
            con.commit()

    elif (mode == "query"):
        emailInput = kwargs.get("email")
        passwordInput = kwargs.get("password")
        cur.execute(f"SELECT id FROM user WHERE email='{emailInput}' AND password='{passwordInput}'")
        loginResult = cur.fetchone()
        if (not loginResult):  # An empty result evaluates to False.
            returnValue = False

    con.close()
    return returnValue