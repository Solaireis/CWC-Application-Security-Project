"""
Routes for the general public and CourseFinity users (Guests, Students, Teachers, and Admins)
"""
# import third party libraries
import markdown, html

# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, Blueprint, Markup, redirect, flash, current_app

# import local python libraries
from python_files.functions.NormalFunctions import get_pagination_arr, EC_verify
from python_files.functions.SQLFunctions import *
from python_files.classes.Reviews import Reviews
from python_files.classes.Course import get_readable_category
from python_files.classes.MarkdownExtensions import AnchorTagExtension
from .RoutesSecurity import limiter

# import python standard libraries
import re

generalBP = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")
limiter.limit(limit_value=current_app.config["CONSTANTS"].REQUEST_LIMIT)(generalBP)

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

    return render_template(
        "users/general/home.html", imageSrcPath=imageSrcPath,
        userPurchasedCourses=userPurchasedCourses,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses), accType=accType
    )

@generalBP.route(current_app.config["CONSTANTS"].REDIRECT_CONFIRMATION_URL)
def redirectConfirmation():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    redirectURL = request.args.get(
        CONSTANTS.REDIRECT_CONFIRMATION_PARAM_NAME, default=None, type=str
    )
    if (redirectURL is None):
        return redirect(url_for("generalBP.home"))

    isValidURL = re.fullmatch(CONSTANTS.URL_REGEX, redirectURL)
    return render_template("users/general/redirect_confirmation.html", imageSrcPath=imageSrcPath, accType=accType, redirectURL=html.escape(redirectURL), isValidURL=isValidURL)

@generalBP.route("/teacher/<string:teacherID>")
def teacherPage(teacherID:str):
    teacherInfo = sql_operation(table="user", mode="get_user_data", userID=teacherID)
    if (teacherInfo is None or teacherInfo.role != "Teacher"):
        abort(404) # prevent users from using other ids except existing teachers

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
    accType = imageSrcPath = userID = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        accType = userInfo.role
        userID = userInfo.uid
        if (accType == "Teacher" and userID == teacherID):
            return redirect(url_for("teacherBP.courseList"))

    page = request.args.get("p", default=1, type=int)
    allCourses = sql_operation(table="course", mode="get_all_courses_by_teacher", pageNum=page, teacherID=teacherID)
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
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courses): #raise exception
        abort(404)

    #create variable to store these values
    courseDescription = Markup(
        markdown.markdown(
            html.escape(courses.courseDescription),
            extensions=[AnchorTagExtension()]
        )
    )
    # print("hi",courses)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=courses.teacherID)
    if (not teacherRecords): #raise exception if teacher records doesnt exist
        abort(404)
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
    else: #if there are no reviews
        pass # Returns the previous var, an empty list

    #TODO: Pagnination required.

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
        if (get_readable_category(courseCategory) != "Unknown Category"):
            listInfo = sql_operation(table="course", mode="explore", courseCategory=searchInput, pageNum=page)
        else: # if no such course category exist, default to "Programming" category
            return redirect(url_for("generalBP.search") + "?ct=Programming")
    else:
        listInfo = sql_operation(table="course", mode="search", searchInput=searchInput, pageNum=page)

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

@generalBP.route("/verify-email/<string:token>")
@limiter.limit("15 per minute")
def verifyEmail(token:str):
    """
    In the general blueprint as a user might change their email when logged in.
    Hence, in this blueprint, it would allow a logged in user to verify their new email.
    """
    if ("admin" in session):
        return redirect(url_for("generalBP.home"))

    # verify the token
    data = EC_verify(data=token, getData=True)
    if (not data.get("verified")):
        # if the token is invalid
        flash("Verify email link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    # check if jwt exists in database
    tokenID = data["data"].get("token_id")
    if (tokenID is None):
        abort(404)
    if (not sql_operation(table="limited_use_jwt", mode="jwt_is_valid", tokenID=tokenID)):
        if ("user" in session):
            flash("Verify email url is invalid or has expired!", "Warning!")
            return redirect(url_for("userBP.userProfile"))
        elif ("user" not in session):
            flash("Verify email url is invalid or has expired!", "Danger")
            return redirect(url_for("guestBP.login"))
        else:
            abort(404)

    # get the userID from the token
    jsonPayload = data["data"]["payload"]
    userID = jsonPayload["userID"]

    # Check if user is logged in, check if the userID in the token
    # matches the userID in the session.
    if ("user" in session and session["user"] != userID):
        flash("Verify email link is invalid or has expired!", "Danger")
        return redirect(url_for("generalBP.home"))

    # check if the user exists in the database
    if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
        # if the user does not exist
        flash("Reset password link is invalid or has expired!", "Danger")
        if ("user" in session):
            session.clear()
        return redirect(url_for("guestBP.login"))

    # check if email has been verified
    if (sql_operation(table="user", mode="email_verified", userID=userID)):
        # if the email has been verified
        if ("user" in session):
            flash("Your email has already been verified!", "Sorry!")
            return redirect(url_for("generalBP.home"))
        else:
            flash("Your email has already been verified!", "Danger")
            return redirect(url_for("guestBP.login"))

    # update the email verified column to true
    sql_operation(table="user", mode="update_email_to_verified", userID=userID)
    sql_operation(table="limited_use_jwt", mode="decrement_limit_after_use", tokenID=tokenID)
    if ("user" in session):
        flash("Your email has been verified!", "Email Verified!")
        return redirect(url_for("generalBP.home"))
    else:
        flash("Your email has been verified!", "Success")
        return redirect(url_for("guestBP.login"))