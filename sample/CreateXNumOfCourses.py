# import third party libraries
import pymysql
from google_crc32c import Checksum as g_crc32c

from pathlib import Path
from sys import path

path.append(str(Path(__file__).parent.parent.joinpath("src", "python_files")))
from StripeFunctions import *   # Yes it works, ignore the error

# import python standard libraries
from random import randint
from six import ensure_binary
import pathlib, uuid
from sys import modules
from importlib.util import spec_from_file_location, module_from_spec
from typing import Union, Optional
from flask_misaka import markdown

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()

# import Constants_Init.py local python module using absolute path
CONSTANTS_INIT_PY_FILE = FILE_PATH.parent.joinpath("src", "python_files", "Constants.py")
spec = spec_from_file_location("Constants_Init", str(CONSTANTS_INIT_PY_FILE))
Constants_Init = module_from_spec(spec)
modules[spec.name] = Constants_Init
spec.loader.exec_module(Constants_Init)

"""----------------------------------- START OF DEFINING FUNCTIONS -----------------------------------"""

def get_mysql_connection(debug:bool=None, database:Optional[str]=Constants_Init.CONSTANTS.DATABASE_NAME) -> pymysql.connections.Connection:
    """
    Get a MySQL connection to the coursefinity database.
    
    Args:
    - debug (bool): whether to connect to the MySQL database locally or to Google CLoud SQL Server
        - Defaults to DEBUG_MODE defined in Constants.py
    - database (str, optional): the name of the database to connect to
        - Defaults to DATABASE_NAME defined in Constants.py if not defined
        - Define database to None if you do not want to connect to a database
    
    Returns:
    A MySQL connection.
    """
    if (debug):
        LOCAL_SQL_CONFIG_COPY = Constants_Init.CONSTANTS.LOCAL_SQL_SERVER_CONFIG.copy()
        if (database is not None):
            LOCAL_SQL_CONFIG_COPY["database"] = database
        connection = pymysql.connect(**LOCAL_SQL_CONFIG_COPY)
        return connection
    else:
        connection: pymysql.connections.Connection = Constants_Init.CONSTANTS.SQL_CLIENT.connect(
            instance_connection_string=Constants_Init.CONSTANTS.SQL_INSTANCE_LOCATION,
            driver="pymysql",
            user="root",
            password=Constants_Init.CONSTANTS.get_secret_payload(secretID="sql-root-password"),
            database=database
        )
        return connection

def generate_id() -> str:
    """
    Generates a unique ID (32 bytes)
    """
    return uuid.uuid4().hex

def crc32c(data:Union[bytes, str]) -> int:
    """
    Calculates the CRC32C checksum of the provided data
    
    Args:
    - data (str|bytes): the bytes of the data which the checksum should be calculated
        - If the data is in string format, it will be encoded to bytes
    
    Returns:
    - An int representing the CRC32C checksum of the provided bytes
    """
    return int(g_crc32c(initial_value=ensure_binary(data)).hexdigest(), 16)

def symmetric_encrypt(plaintext:str="", keyRingID:str="coursefinity-users", keyID:str="") -> bytes:
    """
    Using Google Symmetric Encryption Algorithm, encrypt the provided plaintext.
    
    Args:
    - plaintext (str): the plaintext to encrypt
    - keyRingID (str): the key ring ID
        - Defaults to "coursefinity-users"
    - keyID (str): the key ID/name of the key
    
    Returns:
    - ciphertext (bytes): the ciphertext
    """
    plaintext = plaintext.encode("utf-8")

    # compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
    plaintextCRC32C = crc32c(plaintext)

    # Construct the key version name
    keyVersionName = Constants_Init.CONSTANTS.KMS_CLIENT.crypto_key_path(Constants_Init.CONSTANTS.GOOGLE_PROJECT_ID, Constants_Init.CONSTANTS.LOCATION_ID, keyRingID, keyID)

    # construct and send the request to Google Cloud KMS API to encrypt the plaintext
    response = Constants_Init.CONSTANTS.KMS_CLIENT.encrypt(request={"name": keyVersionName, "plaintext": plaintext, "plaintext_crc32c": plaintextCRC32C})

    # Perform some integrity checks on the encrypted data that Google Cloud KMS API returned
    # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (not response.verified_plaintext_crc32c):
        # request sent to Google Cloud KMS API was corrupted in-transit
        raise Exception("Plaintext CRC32C checksum does not match.")
    if (response.ciphertext_crc32c != crc32c(response.ciphertext)):
        # response received from Google Cloud KMS API was corrupted in-transit
        raise Exception("Ciphertext CRC32C checksum does not match.")

    return response.ciphertext

"""----------------------------------- END OF DEFINING FUNCTIONS -----------------------------------"""

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        debugFlag = True if (debugPrompt != "n") else False
        break

while debugFlag == True:
    stripePrompt = input("Use with Stripe? (Y/n): ").lower().strip()
    if stripePrompt not in ("y", "n", ""):
        print("Invalid input", end = '\n\n')
        continue
    else:
        stripeFlag = True if (stripePrompt != "n") else False
        break

try:
    con = get_mysql_connection(debug=debugFlag)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")

cur = con.cursor()
TEACHER_ROLE_ID = STUDENT_ROLE_ID = None

cur.execute("CALL get_role_id(%(Teacher)s)", {"Teacher":"Teacher"})
TEACHER_ROLE_ID = cur.fetchone()[0]
# cur.callproc("get_role_id", ("Teacher",))
# for result in cur.stored_results():
#     TEACHER_ROLE_ID = result.fetchone()[0]

cur.execute("CALL get_role_id(%(Student)s)", {"Student":"Student"})
STUDENT_ROLE_ID = cur.fetchone()[0]
# cur.callproc("get_role_id", ("Student",))
# for result in cur.stored_results():
#     STUDENT_ROLE_ID = result.fetchone()[0]

TEACHER_UID = "30a749defdd843ecae5da3b26b6d6b9b"
cur.execute("SELECT * FROM user WHERE id='30a749defdd843ecae5da3b26b6d6b9b'")
res = cur.fetchall()
if (not res):
    # add to the mysql database
    userID = TEACHER_UID
    username = "NoobCoderDaniel"
    email = "test@teacher.com"
    keyName = "test-key"
    password = symmetric_encrypt(plaintext=Constants_Init.CONSTANTS.PH.hash("User123!"), keyID=keyName)
    cur.execute("INSERT INTO user (id, role, username, email, password, date_joined, key_name) VALUES (%s, %s, %s, %s, %s, SGT_NOW(), %s)", (userID, TEACHER_ROLE_ID, username, email, password, keyName))
    con.commit()
    cur.execute("INSERT INTO user_ip_addresses (user_id, last_accessed, ip_address) VALUES (%(userID)s, SGT_NOW(), %(ipAddress)s)", {"userID": userID, "ipAddress": "127.0.0.1"})
    con.commit()

if stripeFlag:
    print("Creating 5 courses in line with Stripe data.")
    demoCourse = 5
else:
    demoCourse = int(input("How many courses would you like to create? (Min: 5): "))
    while (demoCourse < 5):
        print("Please enter at least 5.")
        demoCourse = int(input("How many courses would you like to create? (Min: 5): "))

cur.execute(f"SELECT course_name FROM course WHERE teacher_id='{TEACHER_UID}' ORDER BY date_created DESC LIMIT 1")
latestDemoCourse = cur.fetchall()
if (not latestDemoCourse):
    latestDemoCourse = 1
else:
    latestDemoCourse = int(latestDemoCourse[0][0].split(" ")[-1]) + 1

course_id_list = []

for i in range(latestDemoCourse, latestDemoCourse + demoCourse):
    if stripeFlag:
        course_id = f"Test_Course_ID_{i - latestDemoCourse + 1}_v2"
    else:
        course_id = generate_id()
    course_id_list.append(course_id)
    teacher_id = "30a749defdd843ecae5da3b26b6d6b9b"
    course_name = f"Data Structure and Algorithms Demo Course {i}"
    course_description = (f""" This is a demo course for Data Structure and Algorithms.     
    It is a course for students who are interested in learning about Data Structure and Algorithms.    
    In this course you will learn about the following topics:    
    1. Arrays    
    2. Linked Lists    
    3. Stack and Queue    
    4. Trees    
    5. Graphs    
    6. Binary Search Tree    
    7. Red Black Binary Tree    
    8. Binary Heap    
    9. Hash Table    
    10. Advance sorting    
    11. Searching    
    12. Pattern Defeating QuickSort    

    Please click on the following timestamps to skip ahead to the corresponding section:    
    1. [2020-01-01 00:00:00]   
    2. [2020-01-01 00:00:00]   
    3. [2020-01-01 00:00:00]   
    4. [2020-01-01 00:00:00]   

    Thanks for watching the demo course!  
        """)

    course_price = round(i * 50.50, 2)
    course_category = "Other Academics"
    course_total_rating = randint(0, 5)
    course_rating_count = 1

    #video_path = "https://www.youtube.com/embed/dQw4w9WgXcQ" # demo, will be changed to a video path
    video_path = "https://www.youtube.com/embed/L7ESZZkn_z8" # demo uncopyrighted song, will be changed to a video path

    cur.execute("INSERT INTO course (course_id, teacher_id, course_name, course_description, course_price, course_category, course_total_rating, course_rating_count, date_created, video_path) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, SGT_NOW(), %s)", (course_id, teacher_id, course_name, course_description, course_price, course_category, course_total_rating, course_rating_count, video_path))
    #stripe_product_create(courseID=course_id, courseName=course_name, courseDescription=course_description, coursePrice=course_price, debug=True)

# Add student
STUDENT_ID = "76456a9aa7104d7db2c89b24cab697c4"
cur.execute(f"SELECT * FROM user WHERE id='{STUDENT_ID}'")
res = cur.fetchone()
if (res is None):
    # add to the mysql database
    # use first 10 courseIDs as data

    cartData = f'["{course_id_list[0]}", "{course_id_list[1]}", "{course_id_list[2]}"]'
    purchasedData = f'["{course_id_list[3]}", "{course_id_list[4]}"]'

    userID = STUDENT_ID
    username = "Chloe"
    email = "test@student.com"
    keyName = "test-key"
    password = symmetric_encrypt(plaintext=Constants_Init.CONSTANTS.PH.hash("User123!"), keyID=keyName)

    cur.execute("INSERT INTO user (id, role, username, email, password, date_joined, key_name, cart_courses, purchased_courses) VALUES (%s, %s, %s, %s, %s, SGT_NOW(), %s, %s, %s)", (userID, STUDENT_ROLE_ID, username, email, password, keyName, cartData, purchasedData))
    con.commit()
    cur.execute("INSERT INTO user_ip_addresses (user_id, last_accessed, ip_address) VALUES (%(userID)s, SGT_NOW(), %(ipAddress)s)", {"userID": userID, "ipAddress": "127.0.0.1"})
    con.commit()

con.commit()
con.close()

print("Added", demoCourse, "demo courses to the database")