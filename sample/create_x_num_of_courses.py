# import third party libraries
import pymysql, stripe

# import python standard libraries
from random import randint, choice as rand_choice
import pathlib, sys, json
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

CONSTANTS = NormalFunctions.CONSTANTS
THUMBNAILS_PRESET = ["demo_thumbnail_1.webp", "demo_thumbnail_2.webp", "demo_thumbnail_3.webp", "demo_thumbnail_4.webp", "demo_thumbnail_5.webp"]

# Get Stripe API Key
stripe.api_key = CONSTANTS.STRIPE_SECRET_KEY

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
    con = NormalFunctions.get_mysql_connection(debug=debugFlag)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")

cur = con.cursor()
TEACHER_ROLE_ID = STUDENT_ROLE_ID = None

cur.execute("CALL get_role_id(%(Teacher)s)", {"Teacher":"Teacher"})
TEACHER_ROLE_ID = cur.fetchone()[0]

cur.execute("CALL get_role_id(%(Student)s)", {"Student":"Student"})
STUDENT_ROLE_ID = cur.fetchone()[0]

TEACHER_UID = "30a749defdd843ecae5da3b26b6d6b9b"
cur.execute("SELECT * FROM user WHERE id='30a749defdd843ecae5da3b26b6d6b9b'")
res = cur.fetchall()
if (not res):
    # add to the mysql database
    userID = TEACHER_UID
    username = "Daniel Pang"
    email = "daniel@gmail.com"
    password = NormalFunctions.symmetric_encrypt(plaintext=CONSTANTS.PH.hash("User123!"), keyID=CONSTANTS.PEPPER_KEY_ID)
    cur.execute("INSERT INTO user (id, role, username, email, password, date_joined) VALUES (%s, %s, %s, %s, %s, SGT_NOW())", (userID, TEACHER_ROLE_ID, username, email, password))
    con.commit()
    ipAddress = "127.0.0.1"
    ipDetails = json.dumps(CONSTANTS.IPINFO_HANDLER.getDetails(ipAddress).all)
    cur.execute("INSERT INTO user_ip_addresses (user_id, last_accessed, ip_address, ip_address_details) VALUES (%(userID)s, SGT_NOW(), %(ipAddress)s, %(ipDetails)s)", {"userID": userID, "ipAddress": ipAddress, "ipDetails": ipDetails})
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
        course_id = NormalFunctions.generate_id()
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

    Thanks for watching the demo course!  
        """)
    course_image_path = rand_choice(THUMBNAILS_PRESET)
    course_price = round(i * 50.50, 2)
    course_category = "Other Academics"
    course_total_rating = randint(0, 5)
    course_rating_count = 1

    #video_path = "https://www.youtube.com/embed/dQw4w9WgXcQ" # demo, will be changed to a video path
    video_path = "https://www.youtube.com/embed/L7ESZZkn_z8" # demo uncopyrighted song, will be changed to a video path

    cur.execute("INSERT INTO course (course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, course_total_rating, course_rating_count, date_created, video_path) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, SGT_NOW(), %s)", (course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, course_total_rating, course_rating_count, video_path))
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
    password = NormalFunctions.symmetric_encrypt(plaintext=CONSTANTS.PH.hash("User123!"), keyID=CONSTANTS.PEPPER_KEY_ID)

    cur.execute("INSERT INTO user (id, role, username, email, password, date_joined, cart_courses, purchased_courses) VALUES (%s, %s, %s, %s, %s, SGT_NOW(), %s, %s)", (userID, STUDENT_ROLE_ID, username, email, password, cartData, purchasedData))
    con.commit()
    ipAddress = "127.0.0.1"
    ipDetails = json.dumps(CONSTANTS.IPINFO_HANDLER.getDetails(ipAddress).all)
    cur.execute("INSERT INTO user_ip_addresses (user_id, last_accessed, ip_address, ip_address_details) VALUES (%(userID)s, SGT_NOW(), %(ipAddress)s, %(ipDetails)s)", {"userID": userID, "ipAddress": ipAddress, "ipDetails": ipDetails})
    con.commit()

print("Added", demoCourse, "demo courses to the database")

while (1):
    addReviews = input("Do you want to add demo reviews? (Y/n): ").lower().strip()
    if (addReviews not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        #adding reviews to courses
        #STUDENT_ID = "76456a9aa7104d7db2c89b24cab697c4"
        cur.execute(f"SELECT * FROM review WHERE user_id='{STUDENT_ID}'")
        res = cur.fetchone()
        if (res is None):
            
            courseReview = """
            
            Daniel is actually a very helpful person.
            he has shared many tips and tricks to teaching me
            how to do better at data structure and algorithms
            
            """
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
                # print(f"course details {course}")
                # print(f"Added review to course: {courseID}")
            break

con.commit()
con.close()