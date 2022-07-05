# import third party libraries
import pymysql

# import local python libraries
from random import randint
import pathlib, sys
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "python_files", "functions")

# add to sys path so that Constants.py can be imported by NormalFunctions.py
sys.path.append(str(PYTHON_FILES_PATH.parent))

# import NormalFunctions.py local python module using absolute path
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("NormalFunctions.py")
spec = spec_from_file_location("NormalFunctions", str(NORMAL_PY_FILE))
NormalFunctions = module_from_spec(spec)
sys.modules[spec.name] = NormalFunctions
spec.loader.exec_module(NormalFunctions)

# CONSTANTS = NormalFunctions.CONSTANTS

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        debugFlag = True if (debugPrompt != "n") else False
        break

try:
    con = NormalFunctions.get_mysql_connection(debug=debugFlag)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")
cur = con.cursor()

cur.execute(f"SELECT * FROM course")
courses = cur.fetchall()

if courses:
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
            cur.execute(
                "INSERT INTO review ( course_id, user_id, course_rating, course_review, review_date) VALUES (%(courseID)s, %(userID)s, %(courseRating)s, %(courseReview)s, SGT_NOW())", 
                {"courseID": courseID, "userID": userID, "courseRating": courseRating, "courseReview": courseReview}
            )
            con.commit()
            print(f"course details {course}")
            print(f"Added review to course {courseID}")
else:
    print("No courses are made yet, please run the demo create number of courses")

con.close()      


