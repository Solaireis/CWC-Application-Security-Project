# import third party libraries
import mysql.connector
from argon2 import PasswordHasher as PH

# import python standard libraries
from os import environ
from datetime import datetime
from random import randint

# import local python libraries
from python_files.NormalFunctions import generate_id, symmetric_encrypt
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

cur = con.cursor(buffered=True)
TEACHER_ROLE_ID = STUDENT_ROLE_ID = None
cur.callproc("get_role_id", ("Teacher",))
for result in cur.stored_results():
    TEACHER_ROLE_ID = result.fetchone()[0]

cur.callproc("get_role_id", ("Student",))
for result in cur.stored_results():
    STUDENT_ROLE_ID = result.fetchone()[0]

TEACHER_UID = "30a749defdd843ecae5da3b26b6d6b9b"
cur.execute("SELECT * FROM user WHERE id='30a749defdd843ecae5da3b26b6d6b9b'")
res = cur.fetchall()
if (not res):
    # add to the mysql database
    userID = TEACHER_UID
    username = "NoobCoderDaniel"
    email = "test@teacher.com"
    keyName = "test-key"
    password = symmetric_encrypt(plaintext=PH().hash("User123!"), keyID=keyName)
    cur.execute("INSERT INTO user (id, role, username, email, password, key_name) VALUES (%s, %s, %s, %s, %s, %s)", (userID, TEACHER_ROLE_ID, username, email, password, keyName))
    con.commit()

demoCourse = int(input("How many courses would you like to create? (Min: 10): "))
while (demoCourse < 10):
    print("Please enter at least 10.")
    demoCourse = int(input("How many courses would you like to create? (Min: 10): "))

cur.execute(f"SELECT course_name FROM course WHERE teacher_id='{TEACHER_UID}' ORDER BY date_created DESC LIMIT 1")
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
    course_price = round(i * 50.50, 2)
    course_category = "Other Academics"
    course_total_rating = randint(0, 5)
    course_rating_count = 1

    #video_path = "https://www.youtube.com/embed/dQw4w9WgXcQ" # demo, will be changed to a video path
    video_path = "https://www.youtube.com/embed/L7ESZZkn_z8" # demo uncopyrighted song, will be changed to a video path

    cur.execute("INSERT INTO course (course_id, teacher_id, course_name, course_description, course_price, course_category, course_total_rating, course_rating_count, video_path) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", (course_id, teacher_id, course_name, course_description, course_price, course_category, course_total_rating, course_rating_count, video_path))

# Add student
STUDENT_ID = "76456a9aa7104d7db2c89b24cab697c4"
cur.execute(f"SELECT * FROM user WHERE id='{STUDENT_ID}'")
res = cur.fetchone()
if (res is None):
    # add to the mysql database
    # use first 10 courseIDs as data

    cartData = f'["{course_id_list[0]}", "{course_id_list[1]}", "{course_id_list[2]}", "{course_id_list[3]}", "{course_id_list[4]}"]'
    purchasedData = f'["{course_id_list[5]}", "{course_id_list[6]}", "{course_id_list[7]}", "{course_id_list[8]}", "{course_id_list[9]}"]'

    userID = STUDENT_ID
    username = "Chloe"
    email = "test@student.com"
    keyName = "test-key"
    password = symmetric_encrypt(plaintext=PH().hash("User123!"), keyID=keyName)

    cur.execute("INSERT INTO user (id, role, username, email, password, key_name, cart_courses, purchased_courses) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (userID, STUDENT_ROLE_ID, username, email, password, keyName, cartData, purchasedData))
    con.commit()

con.commit()
con.close()

print("Added", demoCourse, "demo courses to the database")