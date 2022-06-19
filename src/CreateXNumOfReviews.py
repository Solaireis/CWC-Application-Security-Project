import sqlite3, pathlib, uuid
import mysql.connector
from os import environ
from datetime import datetime
from random import randint
from python_files.NormalFunctions import generate_id

# pyFilePath = pathlib.Path(__file__).parent.absolute().joinpath("databases", "database.db")

# con = sqlite3.connect(pyFilePath)

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        debugFlag = True if (debugPrompt != "n") else False
        break

if (debugFlag):
    host = "localhost"
    password = environ["LOCAL_SQL_PASS"]
else:
    host = "34.143.163.29" # Google Cloud SQL Public address
    password = environ["REMOTE_SQL_PASS"]

try:
    con = mysql.connector.connect(
        host=host,
        user="root",
        password=password,
        database="coursefinity",
    )
except (mysql.connector.errors.ProgrammingError):
    print("Database Not Found. Please create one first")
cur = con.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id TEXT,
        course_id TEXT,
        course_rating INTEGER,
        course_review TEXT,
        
        PRIMARY KEY (user_id, course_id)
    )""")

