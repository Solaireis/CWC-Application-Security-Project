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
    host = environ["GOOGLE_CLOUD_MYSQL_SERVER"] # Google Cloud SQL Public address
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
cur = con.cursor(buffered=True)

# cur.execute("""CREATE TABLE IF NOT EXISTS user (
#         id VARCHAR(255) PRIMARY KEY, 
#         role VARCHAR(255) NOT NULL,
#         username VARCHAR(255) NOT NULL UNIQUE, 
#         email VARCHAR(255) NOT NULL UNIQUE, 
#         password VARCHAR(255) NOT NULL, 
#         profile_image VARCHAR(255), 
#         date_joined DATE NOT NULL,
#         card_name VARCHAR(255),
#         card_no INTEGER UNIQUE,
#         card_exp VARCHAR(255),
#         card_cvv INTEGER,
#         cart_courses VARCHAR(255) NOT NULL,
#         purchased_courses VARCHAR(255) NOT NULL
#     )""")

cur.execute("SELECT * FROM user WHERE id='30a749defdd843ecae5da3b26b6d6b9b'")
res = cur.fetchall()
if (not res):
    # add to the sqlite3 database
    data = ("30a749defdd843ecae5da3b26b6d6b9b", "Teacher", "Daniel", "test@teacher.com", "123123", None, "2022-05-22", None, None, None,"test-key", "[]", "[]")
    cur.execute("INSERT INTO user VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", data)
    con.commit()

# cur.execute("""CREATE TABLE IF NOT EXISTS course (
#         course_id VARCHAR(255) PRIMARY KEY, 
#         teacher_id VARCHAR(255) NOT NULL,
#         course_name VARCHAR(255) NOT NULL,
#         course_description VARCHAR(255),
#         course_image_path VARCHAR(255),
#         course_price FLOAT NOT NULL,
#         course_category VARCHAR(255) NOT NULL,
#         course_total_rating INTEGER NOT NULL,
#         course_rating_count INTEGER NOT NULL,
#         date_created DATE NOT NULL,
#         video_path VARCHAR(255) NOT NULL,
#         FOREIGN KEY (teacher_id) REFERENCES user(id)
#     )""")

demoCourse = int(input("How many courses would you like to create? (Min: 10): "))
while (demoCourse < 10):
    print("Please enter at least 10.")
    demoCourse = int(input("How many courses would you like to create? (Min: 10): "))

cur.execute(f"SELECT course_name FROM course WHERE teacher_id='30a749defdd843ecae5da3b26b6d6b9b' ORDER BY date_created DESC LIMIT 1")
latestDemoCourse = cur.fetchall()
if (not latestDemoCourse):
    latestDemoCourse = 1
else:
    latestDemoCourse = int(latestDemoCourse[0][0].split(" ")[-1]) + 1

course_id_list = []

for i in range(latestDemoCourse, latestDemoCourse + demoCourse):
    course_id = generate_id()
    course_id_list.append(course_id)
    teacher_id = "30a749defdd843ecae5da3b26b6d6b9b"
    course_name = f"Demo Course {i}"
    course_description = f"This is a demo course, part {i}!"
    course_image_path = None
    course_price = i * 50.50
    course_category = "Other Academics"
    course_total_rating = randint(0, 5)
    course_rating_count = 1

    date_created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #video_path = "https://www.youtube.com/embed/dQw4w9WgXcQ" # demo, will be changed to a video path
    video_path = "https://www.youtube.com/embed/L7ESZZkn_z8" # demo uncopyrighted song, will be changed to a video path
    data = (course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, course_total_rating, course_rating_count, date_created, video_path)
    cur.execute("INSERT INTO course VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", data)

# Add student
cur.execute("SELECT * FROM user WHERE id='76456a9aa7104d7db2c89b24cab697c4'")
res = cur.fetchall()
if (not res):
    # add to the sqlite3 database
    # use first 10 courseIDs as data

    cart_data = f'["{course_id_list[0]}", "{course_id_list[1]}", "{course_id_list[2]}", "{course_id_list[3]}", "{course_id_list[4]}"]'
    purchased_data = f'["{course_id_list[5]}", "{course_id_list[6]}", "{course_id_list[7]}", "{course_id_list[8]}", "{course_id_list[9]}"]'

    data = ("76456a9aa7104d7db2c89b24cab697c4", "Student", "Chloe", "test@student.com", "456456", None, "2022-06-04", None, None, None, "test-key", cart_data, purchased_data)
    cur.execute("INSERT INTO user VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", data)
    con.commit()

con.commit()
con.close()

print("Added", demoCourse, "demo courses to the database")