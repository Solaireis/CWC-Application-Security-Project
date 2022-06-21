# import third party libraries
import mysql.connector

# import local python libraries
from os import environ
from datetime import datetime
from random import randint

# import local python libraries
from python_files.NormalFunctions import generate_id
from python_files.Constants import REMOTE_SQL_SERVER_CONFIG, LOCAL_SQL_SERVER_CONFIG, DATABASE_NAME

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        debugFlag = True if (debugPrompt != "n") else False
        break

if (debugFlag):
    config = LOCAL_SQL_SERVER_CONFIG.copy()
else:
    config = REMOTE_SQL_SERVER_CONFIG.copy()

config["database"] = DATABASE_NAME
try:
    con = mysql.connector.connect(**config)
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

