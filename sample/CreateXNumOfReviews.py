# import third party libraries
import pymysql

# import local python libraries
from datetime import datetime
from random import randint
import pathlib, uuid
from sys import modules
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries using absolute paths
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

"""----------------------------------- START OF DEFINING FUNCTIONS -----------------------------------"""

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

#adding reviews to courses
STUDENT_ID = "76456a9aa7104d7db2c89b24cab697c4"
cur.execute(f"SELECT * FROM review WHERE user_id='{STUDENT_ID}'")
res = cur.fetchone()
if (res is None):
    
    courseReview = "This is a test review"
    userID = STUDENT_ID
    cur.execute(f"SELECT * FROM course")
    res = cur.fetchall()
    for course in res:
        courseRating = randint(1,5)
        
        courseID = course[0]
        cur.execute(f"INSERT INTO review ( course_id, user_id, course_rating, course_review) VALUES ( '{courseID}', '{userID}', '{courseRating}', '{courseReview}')")
        con.commit()
        print(f"course details {course}")
        print(f"Added review to course {courseID}")
        


