"""
This file, when run, creates databases to portray a scenario, using all the
variables in each file to ensure everything can be tested.

This helps support testing for the CRUD processes (not much for 'C').

Please update with variables and relevant shelve files accordingly for testing purposes.
"""



"""Databases"""
from python_files.Admin import Admin
from python_files.Teacher import Teacher
from python_files.Student import Student
from python_files.Course import Course
from python_files.CourseLesson import VideoLesson , ZoomLesson, Lesson
from python_files.Ticket import Ticket
from python_files.Security import sanitise, generate_admin_id
from python_files.IntegratedFunctions import generate_ID, generate_course_ID, generate_ID_to_length, generate_6_char_id
from python_files.Graph import userbaseGraph
from datetime import date, timedelta
import shelve, pathlib

databaseFolder = str(pathlib.Path.cwd()) + "\\databases"

# Open shelve
userBase = shelve.open(databaseFolder + "\\user", "c")
adminBase = shelve.open(databaseFolder + "\\admin", "c")

# Remove all prior entries
userDict = {}
adminDict = {}
courseDict = {}
ticketDict = {}
graphList = []

"""
{"Users":{userID:User()}
         {userID:User()}
         {userID:User()}}
"""
"""
{"Admins":{adminID:Admin()}
          {adminID:Admin()}
          {adminID:Admin()}}
"""
"""
{"Courses":{courseID:Course()}
           {courseID:Course()}
           {courseID:Course()}}
"""

#General
userIDStudent1 = generate_ID(userDict)
username = "James"
email = sanitise("CourseFinity123@gmail.com".lower())
password = "123!@#"
user = Student(userIDStudent1, username, email, password)

# Get corresponding userID for updating/adding to dictionary
userDict[userIDStudent1] = user

#General
userIDStudent2 = generate_ID(userDict)
username = "Daniel"
email = sanitise("abc.net@gmail.com".lower())
password = "456$%^"
user = Student(userIDStudent2, username, email, password)

# Get corresponding userID for updating/adding to dictionary
userDict[userIDStudent2] = user



#General
userIDStudent3 = generate_ID(userDict)
username = "Waffles"
email = sanitise("waffles.net@gmail.com".lower())
password = "456$%^"
user = Student(userIDStudent3, username, email, password)

# Get corresponding userID for updating/adding to dictionary
userDict[userIDStudent3] = user

# Tickets
ticketID = generate_6_char_id(ticketDict)
ticketDict[ticketID] = Ticket(ticketID, userIDStudent3, user.get_acc_type(), username, email, "Bugs", "Too many Pancakes.")



#General
userIDStudent4 = generate_ID(userDict)
username = "MikuChan"
email = sanitise("miku.net@gmail.com".lower())
password = "456$%^"
user = Student(userIDStudent4, username, email, password)

# Get corresponding userID for updating/adding to dictionary
userDict[userIDStudent4] = user

# Tickets
ticketID = generate_6_char_id(ticketDict)
ticketDict[ticketID] = Ticket(ticketID, userIDStudent4, user.get_acc_type(), username, email, "Account", "Is it possible to have animated Profile Pics? I like watermelons.")



#General
userIDStudent5 = generate_ID(userDict)
username = "Edan Pang"
email = sanitise("Edan.net@gmail.com".lower())
password = "456$%^"
user = Student(userIDStudent5, username, email, password)

# Get corresponding userID for updating/adding to dictionary
userDict[userIDStudent5] = user

# Tickets
ticketID = generate_6_char_id(ticketDict)
ticketDict[ticketID] = Ticket(ticketID, userIDStudent5, user.get_acc_type(), username, email, "Jobs", "Hello Jason, can I have a job here? Tell everyone I said hi!")



#General
userIDStudent6 = generate_ID(userDict)
username = "Daniel Fan"
email = sanitise("daniel.net@gmail.com".lower())
password = "456$%^"
user = Student(userIDStudent6, username, email, password)

# Get corresponding userID for updating/adding to dictionary
userDict[userIDStudent6] = user

# Tickets
ticketID = generate_6_char_id(ticketDict)
ticketDict[ticketID] = Ticket(ticketID, userIDStudent5, user.get_acc_type(), username, email, "News", "I have made a video covering your company's interest in Daniel. Please have a look at it and see if there is anything that you would like me to improve for you: https://www.youtube.com/watch?v=0Tz-Zd9Vr08")



"""Teacher 1"""

#General
userIDAvery = generate_ID(userDict)
username = "Avery"
email = sanitise("ice_cream@gmail.com".lower())
password = "789&*("
user = Teacher(userIDAvery, username, email, password)

#Teacher
user.set_earnings("5")
user.set_accumulated_earnings("100")
user.update_teacher_join_date_to_today()

userDict[userIDAvery] = user
#Courses (Royston)

#Courses Teaching (Wei Ren)
title = "Making Web Apps The Easy Way (Spoilers: You can't!)"
description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_2.webp"
zoomPrice = "{:,.2f}".format(72.5)
courseType = "Zoom" ## Zoom or Video

courseID = generate_course_ID(courseDict)
course = Course(courseID, courseType, zoomPrice, "Web_Development", title, description, thumbnail, userIDAvery)

course.add_review(userIDStudent2, "Good course to be honest", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "4")

course.set_views(13)

title = "How to make a web app part 1"
description = "You will learn the ups & downs here."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_1.webp"
zoomURL = "https://www.youtube.com/watch?v=SUugKFRhaQ4"
zoomPassword= "abc123"

course.add_zoom_lessons(title, description, thumbnail, zoomURL, zoomPassword, "13:00", "Monday")

title = "How to make a web app part 2"
description = "You will now learn about the birds and the bees."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_1.webp"
zoomURL = "https://www.youtube.com/watch?v=g_vV3bE3GNo"
zoomPassword= "123abc"

course.add_zoom_lessons(title, description, thumbnail, zoomURL, zoomPassword, "15:00", "Wednesday")

user.set_courseTeaching(courseID)

# Get corresponding userID for updating/adding to dictionary
courseDict[courseID] = course

"""Teacher 2"""

#General
userID = generate_ID(userDict)
username = "Sara"
email = sanitise("tourism@gmail.com".lower())
password = "0-=)_+"
user = Teacher(userID, username, email, password)

#Teacher
user.set_earnings("100")
user.update_teacher_join_date_to_today()
user.set_accumulated_earnings("10")
"""
#Cashout Info
user.set_cashoutPreference("Phone")
user.set_cashoutContact("+6512345678")
"""
#Courses (Royston)

userDict[userID] = user

#Courses Teaching (Wei Ren)
title = "Using Math to Find When Your Dad is Coming Home"
description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_1.webp"
price = "{:,.2f}".format(69)
courseType = "Video"

courseID = generate_course_ID(courseDict)
course = Course(courseID, courseType, price, "Math", title, description, thumbnail, userID)


course.add_review(userIDStudent2, "Good course to be honest", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "5")

course.add_review(userIDStudent3, "Welp, that was disappointing!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "1")

course.add_review(userIDStudent4, "Not worth your money and time", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "3")

course.add_review(userIDStudent5, "Actually enjoyed learning from this course", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "4")

course.add_review(userIDStudent6, "I agree, god tier course!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "5")

course.set_views(1)

courseDict[courseID] = course

title = "How to be a Daniel"
description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_3.webp"
price = "{:,.2f}".format(69)
courseType = "Video"

courseID = generate_course_ID(courseDict)
course = Course(courseID, courseType, price, "Other_Academics", title, description, thumbnail, userID)

# def __init__(self, userID, title, comment, rating)
course.add_review(userIDStudent1, "Very god tier course!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "5")

course.set_views(570)

user.set_courseTeaching(courseID)

title = "How to be a daniel part 1"
description = "You will learn the ups & up here."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_1.webp"
videoPath = "".join(["/static/course_videos/", courseID,"/Aiming at legs.mp4"])

course.add_video_lesson(title, description, thumbnail, videoPath)

title = "How to make a daniel part 2"
description = "You will now learn about the bees and the birds."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_1.webp"
videoPath = "".join(["/static/course_videos/", courseID, "/Test_video.mp4"])

print(f"Please change demo video folder to {courseID}")

course.add_video_lesson(title, description, thumbnail, videoPath)

courseDict[courseID] = course


title = "How to be a Daniel 2"
description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
thumbnail = "/static/images/courses/thumbnails/course_thumbnail_3.webp"
videoPrice = "{:,.2f}".format(69)
courseType = "Video"

courseID = generate_course_ID(courseDict)
course = Course(courseID, courseType, videoPrice, "Other_Academics", title, description, thumbnail, userID)

# def __init__(self, userID, title, comment, rating)
course.add_review(userIDStudent1, "A sequel to the very god tier course!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "5")

course.add_review(userIDStudent2, "The best course for becoming a better self!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "5")

course.add_review(userIDStudent3, "Welp, that was disappointing!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "1")

course.add_review(userIDStudent4, "Not worth your money and time", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "3")

course.add_review(userIDStudent5, "Actually enjoyed learning from this course", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "4")

course.add_review(userIDStudent6, "I agree, god tier course!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "5")

course.add_review(userIDAvery, "Enjoyed the course", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.", "4")

AveryUserObject = userDict.get(userIDAvery)

simulatedPurchaseDict = {}
simulatedPurchaseDict[courseID] = {'Course ID' : courseID, "Date" : date.today(), 'Time' : "13:59 (Example)", 'Cost' : 129, "PayPalOrderID" : "simulatedOrderIDExample", "PayPalAccountID" : "SimulatedPayerIDExample"}

AveryUserObject.set_purchases(simulatedPurchaseDict)

course.set_views(1000)

user.set_courseTeaching(courseID)

courseDict[courseID] = course

"""Admin 1"""
#General
adminID = generate_admin_id(adminDict)
username = "The Archivist"
email = sanitise("O52@SCP.com".lower())
password = "27sb2we9djaksidu8a"
admin = Admin(adminID, username, email, password)

#Admin

adminDict[adminID] = admin

"""Admin 2"""
#General
adminID = generate_admin_id(adminDict)
username = "Tamlin"
email = sanitise("O513@SCP.com".lower())
password = "o4jru5fjr49f8ieri4"
admin = Admin(adminID, username, email, password)

adminDict[adminID] = admin

#Admin

# Get corresponding userID for updating/adding to dictionary
adminDict[adminID] = admin

"""Admin 3"""
#General
adminID = generate_admin_id(adminDict)
username = "test"
email = sanitise("test@test.com".lower())
password = "123123123"
admin = Admin(adminID, username, email, password)

#Admin

adminDict[adminID] = admin




# Add courses
user = userDict[list(userDict.keys())[0]]
course = courseDict[list(courseDict.keys())[0]]
user.add_to_cart(course.get_courseID()) # Course ID '0' is "Making Web Apps The Easy Way (Spoilers: You can't!)"

print(user.get_shoppingCart())


# set some data for user base graph for admin dashboard
todayDate = date.today()

graphList = [userbaseGraph(1), userbaseGraph(3), userbaseGraph(3), userbaseGraph(4), userbaseGraph(10), userbaseGraph(25), userbaseGraph(150), userbaseGraph(200), userbaseGraph(180), userbaseGraph(300), userbaseGraph(350), userbaseGraph(400), userbaseGraph(422), userbaseGraph(425), userbaseGraph(600), userbaseGraph(623), userbaseGraph(712), userbaseGraph(723), userbaseGraph(600), userbaseGraph(650), userbaseGraph(690), userbaseGraph(790), userbaseGraph(900), userbaseGraph(1500), userbaseGraph(1600), userbaseGraph(1700), userbaseGraph(2000), userbaseGraph(2300), userbaseGraph(2600), userbaseGraph(3219)]

for i in range(len(graphList)-1, -1, -1):
    graphList[i].set_date(todayDate - timedelta(days=30-i))

# Overwrite entire shelve with updated dictionary
userBase["Users"] = userDict
adminBase["Admins"] = adminDict
userBase["Courses"] = courseDict
userBase["userGraphData"] = graphList
adminBase["Tickets"] = ticketDict

# Make sure to close!
userBase.close()
adminBase.close()
