"""
Routes for the general public and CourseFinity users (Guests, Students, Teachers, and Admins)
"""
# import third party libraries
import markdown

# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, Blueprint, Markup, redirect

# import local python libraries
from python_files.functions.NormalFunctions import get_pagination_arr
from python_files.functions.SQLFunctions import *
from python_files.classes.Reviews import Reviews
from python_files.classes.MarkdownExtensions import AnchorTagPreExtension, AnchorTagPostExtension

generalBP = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")

@generalBP.route("/")
def home():
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", user="guest")
    threeHighlyRatedCourses = sql_operation(table="course", mode="get_3_highly_rated_courses", user="guest")

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
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", user="guest", teacherID=teacherID, getTeacherUsername=False)
    threeHighlyRatedCourses, teacherUsername = sql_operation(table="course", mode="get_3_highly_rated_courses", user="guest", teacherID=teacherID, getTeacherUsername=True)

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
    accType = imageSrcPath = userID = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        accType = userInfo.role
        userID = userInfo.uid
        if (accType == "Teacher" and userID == teacherID):
            return redirect(url_for("teacherBP.courseList"))

    page = request.args.get("p", default=1, type=int)
    allCourses = sql_operation(table="course", mode="get_all_courses_by_teacher", user="guest", pageNum=page, teacherID=teacherID)
    maxPage = 0
    if (len(allCourses) != 0):
        courseList, maxPage = allCourses[0], allCourses[1]         
        if (page > maxPage):
            return redirect(url_for("generalBP.allCourses", teacherID=teacherID) + "?p=" + str(maxPage))

        # Compute the buttons needed for pagination
        paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)

    return render_template("users/general/course_list.html", imageSrcPath=imageSrcPath, courseListLen=len(courseList), accType=accType, currentPage=page, maxPage=maxPage, courseList=courseList, teacherID=teacherID, isOwnself=False, paginationArr=paginationArr, userID=userID)


@generalBP.route("/course/<string:courseID>")
def coursePage(courseID:str):
    # print(courseID)
    courses = sql_operation(table="course", mode="get_course_data", user="guest", courseID=courseID)
    if (not courses): #raise exception
        abort(404)
    #create variable to store these values
    courseDescription = Markup(
        markdown.markdown(
            courses.courseDescription,
            extensions=[AnchorTagPreExtension(), AnchorTagPostExtension()], 
        )
    )
    # print("hi",courses)
    teacherRecords = sql_operation(table="user", mode="get_user_data", user="guest", userID=courses.teacherID)
    teacherName = teacherRecords.username
    teacherProfilePath = teacherRecords.profileImage

    retrieveReviews = sql_operation(table="review", mode="retrieve_all", user="guest", courseID=courseID)
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

# @generalBP.route("/explore/<string:courseCategory>")
# def exploreCategory(courseCategory:str):
#     page = request.args.get("p", default=1, type=int)
#     listInfo = sql_operation(table="course", mode="explore", courseCategory=courseCategory, pageNum=page)
#     if (listInfo):
#         foundResults, maxPage = listInfo[0], listInfo[1]
#         if (page > maxPage):
#             abort(404)

#         if ("user" in session or "admin" in session):
#             userInfo = get_image_path(session["user"], returnUserInfo=True)
#             return render_template("users/general/search.html", searchInput=courseCategory, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), imageSrcPath=userInfo.profileImage, maxPage=maxPage, accType=userInfo.role)

#         return render_template("users/general/search.html", searchInput=courseCategory, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), maxPage=maxPage, accType=None)

#     if ("user" in session or "admin" in session):
#         userInfo = get_image_path(session["user"], returnUserInfo=True)
#         return render_template("users/general/search.html", searchInput=courseCategory, foundResultsLen=0, imageSrcPath=userInfo.profileImage, accType=userInfo.role)

#     return render_template("users/general/search.html", searchInput=courseCategory, foundResults=None, foundResultsLen=0, accType=None)

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
    searchInput = request.args.get("q", default=None, type=str)
    courseCategory = request.args.get("ct", default=None, type=str)

    if (searchInput is None and courseCategory is None):
        # No get parameters
        searchInput = "Courses"
        tagSearch = False
    elif (searchInput is not None and courseCategory is not None):
        # Both get parameters
        searchInput = courseCategory
        tagSearch = True
    elif (searchInput is None and courseCategory is not None):
        # Only courseCategory get parameter
        searchInput = courseCategory
        tagSearch = True
    else:
        # Only searchInput get parameter
        searchInput = searchInput
        tagSearch = False

    # Reduce the length of the query if > 100 characters
    # to prevent buffer overflow attacks
    if (len(searchInput) > 100):
        searchInput = searchInput[:100]

    page = request.args.get("p", default=1, type=int)
    if (courseCategory):
        listInfo = sql_operation(table="course", mode="explore", user="guest", courseCategory=courseCategory, pageNum=page)
    else:
        listInfo = sql_operation(table="course", mode="search", user="guest", searchInput=searchInput, pageNum=page)

    if (listInfo):
        foundResults, maxPage = listInfo[0], listInfo[1]
        if (page > maxPage):
            # TODO: Protect against injections
            if (courseCategory):
                return redirect(url_for('generalBP.search') + "?ct=" + searchInput + "&p=" + str(maxPage))
            else:
                return redirect(url_for('generalBP.search') + "?q=" + searchInput + "&p=" + str(maxPage))

        # Compute the buttons needed for pagination
        paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)

        if ("user" in session or "admin" in session):
            userInfo = get_image_path(session["user"], returnUserInfo=True)
            return render_template("users/general/search.html", searchInput=searchInput, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), imageSrcPath=userInfo.profileImage, maxPage=maxPage, accType=userInfo.role, paginationArr=paginationArr, tagSearch=tagSearch)

        return render_template("users/general/search.html", searchInput=searchInput, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), maxPage=maxPage, accType=None, paginationArr=paginationArr, tagSearch=tagSearch)

    if ("user" in session or "admin" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        return render_template("users/general/search.html", searchInput=searchInput, foundResultsLen=0, imageSrcPath=userInfo.profileImage, accType=userInfo.role, tagSearch=tagSearch)

    return render_template("users/general/search.html", searchInput=searchInput, foundResults=None, foundResultsLen=0, accType=None, tagSearch=tagSearch)