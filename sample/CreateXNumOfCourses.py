# import third party libraries
import pymysql.cursors
from google_crc32c import Checksum as g_crc32c

# import python standard libraries
from random import randint
from six import ensure_binary
import pathlib, uuid
from sys import modules
from importlib.util import spec_from_file_location, module_from_spec
from typing import Union

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()

# import Constants_Init.py local python module using absolute path
CONSTANTS_INIT_PY_FILE = FILE_PATH.parent.joinpath("src", "python_files", "ConstantsInit.py")
spec = spec_from_file_location("Constants_Init", str(CONSTANTS_INIT_PY_FILE))
Constants_Init = module_from_spec(spec)
modules[spec.name] = Constants_Init
spec.loader.exec_module(Constants_Init)

"""----------------------------------- START OF DEFINING FUNCTIONS -----------------------------------"""

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
    keyVersionName = Constants_Init.KMS_CLIENT.crypto_key_path(Constants_Init.GOOGLE_PROJECT_ID, Constants_Init.LOCATION_ID, keyRingID, keyID)

    # construct and send the request to Google Cloud KMS API to encrypt the plaintext
    response = Constants_Init.KMS_CLIENT.encrypt(request={"name": keyVersionName, "plaintext": plaintext, "plaintext_crc32c": plaintextCRC32C})

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

if (debugFlag):
    config = Constants_Init.LOCAL_SQL_SERVER_CONFIG.copy()
else:
    config = Constants_Init.REMOTE_SQL_SERVER_CONFIG.copy()

config["database"] = Constants_Init.DATABASE_NAME
try:
    con = pymysql.connect(**config)
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
    password = symmetric_encrypt(plaintext=Constants_Init.PH.hash("User123!"), keyID=keyName)
    cur.execute("INSERT INTO user (id, role, username, email, password, key_name) VALUES (%s, %s, %s, %s, %s, %s)", (userID, TEACHER_ROLE_ID, username, email, password, keyName))
    con.commit()
    cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address) VALUES (%(userID)s, %(ipAddress)s)", {"userID": userID, "ipAddress": "127.0.0.1"})
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
    password = symmetric_encrypt(plaintext=Constants_Init.PH.hash("User123!"), keyID=keyName)

    cur.execute("INSERT INTO user (id, role, username, email, password, key_name, cart_courses, purchased_courses) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (userID, STUDENT_ROLE_ID, username, email, password, keyName, cartData, purchasedData))
    con.commit()
    cur.execute("INSERT INTO user_ip_addresses (user_id, ip_address) VALUES (%(userID)s, %(ipAddress)s)", {"userID": userID, "ipAddress": "127.0.0.1"})
    con.commit()

con.commit()
con.close()

print("Added", demoCourse, "demo courses to the database")