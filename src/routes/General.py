"""
Routes for the general public and CourseFinity users (Guests, Students, Teachers, and Admins)
"""
# import third party libraries
import markdown

# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, Blueprint, Markup, redirect

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.classes.Reviews import Reviews
from python_files.classes.MarkdownExtensions import AnchorTagPreExtension, AnchorTagPostExtension

generalBP = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")

@generalBP.route("/")
def home():
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses")
    threeHighlyRatedCourses = sql_operation(table="course", mode="get_3_highly_rated_courses")

    userPurchasedCourses = []
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo.purchasedCourses
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/home.html", imageSrcPath=imageSrcPath,
        userPurchasedCourses=userPurchasedCourses,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses), accType=accType)

@generalBP.route("/teacher/<string:teacherID>")
def teacherPage(teacherID:str):
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", teacherID=teacherID, getTeacherUsername=False)
    threeHighlyRatedCourses, teacherUsername = sql_operation(table="course", mode="get_3_highly_rated_courses", teacherID=teacherID, getTeacherUsername=True)

    teacherProfilePath = get_image_path(userID=teacherID)

    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo.purchasedCourses
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage

    return render_template("users/general/teacher_page.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherUsername=teacherUsername,
        teacherProfilePath=teacherProfilePath, teacherID=teacherID,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses), accType=accType)

@generalBP.route("/all-courses/<string:teacherID>")
def allCourses(teacherID:str):
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        accType = userInfo.role
        if (accType == "Teacher") and (userInfo.uid == teacherID):
            return redirect(url_for('teacherBP.courseList'))

    page = request.args.get("p", default=1, type=int)
    allCourses = sql_operation(table="course", mode="get_all_courses_by_teacher", pageNum=page, teacherID=teacherID)
    maxPage = 0
    if len(allCourses)!= 0:
        courseList, maxPage = allCourses[0], allCourses[1]         
        if (page > maxPage):
            abort(404)
    
    return render_template("users/teacher/course_list.html", imageSrcPath=imageSrcPath, courseListLen=len(courseList), accType=accType, currentPage=page, maxPage=maxPage, courseList=courseList, teacherID=teacherID)


@generalBP.route("/course/<string:courseID>")
def coursePage(courseID:str):
    # print(courseID)
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courses): #raise exception
        abort(404)
    #create variable to store these values
    courseDescription = Markup(
        markdown.markdown(
            courses.courseDescription,
            extensions=[AnchorTagPreExtension(), AnchorTagPostExtension()]
        )
    )
    # print("hi",courses)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=courses.teacherID)
    teacherName = teacherRecords.username
    teacherProfilePath = teacherRecords.profileImage

    retrieveReviews = sql_operation(table="review", mode="retrieve_all", courseID=courseID)
    # print("the reviews", retrieveReviews)
    reviewList = [] #list to store all the reviews
    if retrieveReviews: #if there are reviews
        for tupleData in retrieveReviews:
            reviewUserID = tupleData[0]
            reviewInfo = get_image_path(reviewUserID, returnUserInfo=True)
            imageSrcPath = reviewInfo.profileImage
            reviewList.append(Reviews(tupleData=tupleData, courseID=courseID, profileImage=imageSrcPath))

    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        userPurchasedCourses = userInfo.purchasedCourses
        accType = userInfo.role

    return render_template(
        "users/general/course_page.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherName, teacherProfilePath=teacherProfilePath,
        accType=accType, reviewList= reviewList, courses=courses, courseDescription=courseDescription
    )

@generalBP.route("/search")
def search():
    """
    Search for courses

    E.g. of a search query:
    /search?q=DSA&p=2 # page 1 will not have any p argument but can have p=1 argument

    One good example is GitHub's search, notice how the url works.
    E.g. 
    - https://github.com/search?q=test&type=Repositories
    - https://github.com/search?p=2&q=test&type=Repositories
    
    TODO: Must handle all sorts of situation such as manually tampering with the url
    """
    searchInput = request.args.get("q", default="Courses", type=str)
    if (len(searchInput) > 100):
        abort(413)

    page = request.args.get("p", default=1, type=int)
    listInfo = sql_operation(table="course", mode="search", searchInput=searchInput, pageNum=page)
    if (listInfo):
        foundResults, maxPage = listInfo[0], listInfo[1]
        if (page > maxPage):
            abort(404)

        if ("user" in session or "admin" in session):
            userInfo = get_image_path(session["user"], returnUserInfo=True)
            return render_template("users/general/search.html", searchInput=searchInput, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), imageSrcPath=userInfo.profileImage, maxPage=maxPage, accType=userInfo.role)

        return render_template("users/general/search.html", searchInput=searchInput, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), maxPage=maxPage, accType=None)

    if ("user" in session or "admin" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        return render_template("users/general/search.html", searchInput=searchInput, foundResultsLen=0, imageSrcPath=userInfo.profileImage, accType=userInfo.role)

    return render_template("users/general/search.html", searchInput=searchInput, foundResults=None, foundResultsLen=0, accType=None)