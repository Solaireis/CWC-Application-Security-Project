import mysql.connector
from os import environ

def init(debug:bool=False) -> mysql.connector.connection.MySQLConnection:
    """
    Initialize the database with the necessary tables

    Args:
        debug (bool): If true, will initialise locally, else will initialise remotely
    
    Returns:
        The connection to the database (mysql connection object)
    """
    if (debug):
        host = "localhost"
        password = environ["SQL_PASS"]
    else:
        host = "34.143.163.29" # Google Cloud SQL Public address
        password = environ["REMOTE_SQL_PASS"]
    
    mydb = mysql.connector.connect(
        host=host,
        user="root",
        password=password
    )

    cur = mydb.cursor()
    cur.execute("CREATE DATABASE coursefinity")
    mydb.commit()

    mydb.close()

    mydb = mysql.connector.connect(
        host=host,
        user="root",
        password=password,
        database="coursefinity"
    )
    cur = mydb.cursor()

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

    cur.execute("""CREATE TABLE IF NOT EXISTS course (
        course_id VARCHAR(255) PRIMARY KEY, 
        teacher_id VARCHAR(255) NOT NULL,
        course_name VARCHAR(255) NOT NULL,
        course_description VARCHAR(255),
        course_image_path VARCHAR(255),
        course_price FLOAT NOT NULL,
        course_category VARCHAR(255) NOT NULL,
        course_total_rating INTEGER NOT NULL,
        course_rating_count INTEGER NOT NULL,
        date_created DATETIME NOT NULL,
        video_path VARCHAR(255) NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS twofa_token (
        token VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        user_id VARCHAR(255) PRIMARY KEY,
        attempts INTEGER NOT NULL,
        reset_date DATE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS session (
        session_id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        expiry_date DATE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS cart (
        user_id VARCHAR(255),
        course_id VARCHAR(255),
        PRIMARY KEY (user_id, course_id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS purchased (
        user_id VARCHAR(255),
        course_id VARCHAR(255),
        PRIMARY KEY (user_id, course_id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id VARCHAR(255),
        course_id VARCHAR(255),
        course_rating INTEGER,
        course_review VARCHAR(255),
        
        PRIMARY KEY (user_id, course_id)
    )""")

    mydb.commit()
    return mydb