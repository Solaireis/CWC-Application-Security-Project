"""
Routes for the general public and CourseFinity users (Guests, Students, Teachers, and Admins)
"""
# import third party libraries
import markdown

# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, Blueprint, Markup, redirect, flash, current_app

# import local python libraries
from python_files.functions.NormalFunctions import get_pagination_arr, EC_verify, create_assessment, score_within_acceptable_threshold
from python_files.functions.SQLFunctions import *
from python_files.classes.Course import get_readable_category
from python_files.classes.Forms import ContactUsForm
from python_files.classes.MarkdownExtensions import AnchorTagExtension
from .RoutesSecurity import limiter

# import python standard libraries
import re, html

generalBP = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")
limiter.limit(limit_value=current_app.config["CONSTANTS"].DEFAULT_REQUEST_LIMIT)(generalBP)

@generalBP.route("/favicon.ico")
def favicon():
    return redirect("https://storage.googleapis.com/coursefinity/web-assets/common/favicon.ico", code=301)

@generalBP.route("/")
def home():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    if (accType not in ("Student", "Teacher")):
        userID = None
    else:
        userID = session["user"]

    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", userID=userID)
    threeHighlyRatedCourses = sql_operation(table="course", mode="get_3_highly_rated_courses", userID=userID)

    return render_template(
        "users/general/home.html", imageSrcPath=imageSrcPath,
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
        current_app.config["CONSTANTS"].REDIRECT_CONFIRMATION_PARAM_NAME, default=None, type=str
    )
    if (redirectURL is None):
        return redirect(url_for("generalBP.home"))

    isValidURL = re.fullmatch(current_app.config["CONSTANTS"].URL_REGEX, redirectURL)
    return render_template("users/general/redirect_confirmation.html", imageSrcPath=imageSrcPath, accType=accType, redirectURL=html.escape(redirectURL), isValidURL=isValidURL)

@generalBP.route("/teacher/<string:teacherID>")
def teacherPage(teacherID:str):
    teacherInfo = sql_operation(table="user", mode="get_user_data", userID=teacherID)
    if (teacherInfo is None or teacherInfo.role != "Teacher"):
        abort(404) # prevent users from using other ids except existing teachers

    teacherProfilePath = get_image_path(userID=teacherID)

    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage

    if (accType not in ("Student", "Teacher")):
        userID = None
    else:
        userID = session["user"]

    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", teacherID=teacherID, getTeacherUsername=False, userID=userID)
    threeHighlyRatedCourses, teacherUsername = sql_operation(table="course", mode="get_3_highly_rated_courses", teacherID=teacherID, getTeacherUsername=True, userID=userID)

    return render_template("users/general/teacher_page.html",
        imageSrcPath=imageSrcPath, teacherUsername=teacherUsername,
        teacherProfilePath=teacherProfilePath, teacherID=teacherID,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses), accType=accType
    )

@generalBP.route("/teacher/<string:teacherID>/courses")
def allCourses(teacherID:str):
    page = request.args.get("p", default=1, type=int)
    if (page < 1):
        return redirect(url_for("generalBP.allCourses", teacherID=teacherID) + "?p=1")

    accType = imageSrcPath = userID = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        accType = userInfo.role
        userID = userInfo.uid
        if (accType == "Teacher" and userID == teacherID):
            return redirect(url_for("teacherBP.courseList"))

    if (accType not in ("Student", "Teacher")):
        userID = None
    else:
        userID = session["user"]

    courseList, maxPage, teacherName = sql_operation(
        table="course", mode="get_all_courses_by_teacher", pageNum=page, 
        teacherID=teacherID, getTeacherName=True, userID=userID
    )
    paginationArr = []  
    if (page > maxPage):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].PAGE_NUM_REGEX, f"p={maxPage}", request.url, count=1)
        )

    # Compute the buttons needed for pagination
    if (courseList):
        paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)

    return render_template("users/general/course_list.html", imageSrcPath=imageSrcPath, courseListLen=len(courseList), accType=accType, currentPage=page, maxPage=maxPage, courseList=courseList, teacherID=teacherID, isOwnself=False, paginationArr=paginationArr, userID=userID, teacherName=teacherName)

@generalBP.route("/course/<string:courseID>/reviews")
def reviewPage(courseID:str):
    pageNum = request.args.get("p", default=1, type=int)
    if (pageNum < 1):
        return redirect(url_for("userBP.reviewPage", courseID=courseID) + f"?p=1")

    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courses): #raise exception
        abort(404)

    accType = imageSrcPath = None
    purchased = isInCart = False
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        isInCart, purchased = sql_operation(
            table="cart", mode="check_if_purchased_or_in_cart", userID=session["user"], courseID=courseID
        )
        accType = userInfo.role

    reviewArr, maxPage = sql_operation(table="review", mode="paginate_reviews", courseID=courseID, pageNum=pageNum)

    if (pageNum > maxPage):
        return redirect(url_for("userBP.reviewPage", courseID=courseID) + f"?p={maxPage}")

    if (reviewArr):
        paginationArr = get_pagination_arr(pageNum=pageNum, maxPage=maxPage)

    return render_template(
        "users/general/review_page.html",
        imageSrcPath=imageSrcPath, purchased=purchased, isInCart=isInCart, paginationArr=paginationArr,
        accType=accType, reviewArr=reviewArr, courses=courses, maxPage=maxPage, currentPage=pageNum
    )

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
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=courses.teacherID)
    if (not teacherRecords): #raise exception if teacher records doesnt exist
        abort(404)

    teacherName = teacherRecords.username
    teacherProfilePath = teacherRecords.profileImage

    threeLatestReview = sql_operation(table="review", mode="get_3_latest_user_review", courseID=courseID)

    accType = imageSrcPath = None
    purchased = isInCart = False
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        imageSrcPath = userInfo.profileImage
        isInCart, purchased = sql_operation(
            table="cart", mode="check_if_purchased_or_in_cart", userID=session["user"], courseID=courseID
        )
        accType = userInfo.role

    return render_template(
        "users/general/course_page.html",
        imageSrcPath=imageSrcPath, purchased=purchased, isInCart=isInCart, teacherName=teacherName, teacherProfilePath=teacherProfilePath,
        accType=accType, threeLatestReview=threeLatestReview, courses=courses, courseDescription=courseDescription
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
    page = request.args.get("p", default=1, type=int)
    if (page < 1):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].NEGATIVE_PAGE_NUM_REGEX, "p=1", request.url, count=1)
        )

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

    if (courseCategory):
        if (get_readable_category(courseCategory) != "Unknown Category"):
            listInfo = sql_operation(table="course", mode="explore", courseCategory=searchInput, pageNum=page)
        else: # if no such course category exist, default to "Programming" category
            return redirect(url_for("generalBP.search") + "?ct=Programming")
    else:
        listInfo = sql_operation(table="course", mode="search", searchInput=searchInput, pageNum=page)

    foundResults, maxPage = [], 1
    if (listInfo):
        foundResults, maxPage = listInfo[0], listInfo[1]

    if (page > maxPage):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].PAGE_NUM_REGEX, f"p={maxPage}", request.url, count=1)
        )

    # Compute the buttons needed for pagination
    paginationArr = []
    if (listInfo):
        paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)

    accType = imageSrcPath = None
    if ("user" in session or "admin" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage

    return render_template("users/general/search.html", searchInput=searchInput, currentPage=page, foundResults=foundResults, foundResultsLen=len(foundResults), imageSrcPath=imageSrcPath, maxPage=maxPage, accType=accType, paginationArr=paginationArr, tagSearch=tagSearch)

@generalBP.route("/verify-email/<string:token>")
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
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

@generalBP.route("/about-us")
def aboutUs():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/about_us.html", accType=accType, imageSrcPath=imageSrcPath)

@generalBP.route("/terms-and-conditions")
def tos():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/terms_and_conditions.html", accType=accType, imageSrcPath=imageSrcPath)

@generalBP.route("/privacy-policy")
def privacyPolicy():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/privacy_policy.html", accType=accType, imageSrcPath=imageSrcPath)

@generalBP.route("/cookie-policy")
def cookiePolicy():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/cookie_policy.html", accType=accType, imageSrcPath=imageSrcPath)

@generalBP.route("/faq")
def faq():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/faq.html", accType=accType, imageSrcPath=imageSrcPath)

@generalBP.route("/contact-us", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def contactUs():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    contactUsForm = ContactUsForm(request.form)
    if (request.method == "POST" and contactUsForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!", "Form Was Not Submitted")
            return render_template(
                "users/general/contact_us.html", accType=accType, imageSrcPath=imageSrcPath, form=contactUsForm
            )

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="contact_form")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!", "Form Was Not Submitted")
            return render_template(
                "users/general/contact_us.html", accType=accType, imageSrcPath=imageSrcPath, form=contactUsForm
            )

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!", "Form Was Not Submitted")
            return render_template(
                "users/general/contact_us.html", accType=accType, imageSrcPath=imageSrcPath, form=contactUsForm
            )

        email = contactUsForm.email.data.lower()
        if (email in current_app.config["CONSTANTS"].COURSEFINITY_SUPPORT_EMAILS):
            flash(
                Markup("You can't just use our support email and expect the support team to help themselves. However, as a token of appreciation, you can click <a href='https://youtu.be/dQw4w9WgXcQ' target='_blank' rel='nofollow noopener'>here</a> for one of our easter eggs."),
                "Excuse me!?"
            )
            return render_template(
                "users/general/contact_us.html", accType=accType, imageSrcPath=imageSrcPath, form=contactUsForm
            )

        name = contactUsForm.name.data
        enquiryType = contactUsForm.enquiryType.data.title()
        if (enquiryType not in current_app.config["CONSTANTS"].SUPPORT_ENQUIRY_TYPE):
            flash("Please select a valid enquiry type!", "Invalid Enquiry Type!")
            return render_template(
                "users/general/contact_us.html", accType=accType, imageSrcPath=imageSrcPath, form=contactUsForm
            )

        enquiryType = f"Support Enquiry: {enquiryType}"
        enquiry = contactUsForm.enquiry.data
        bodyHtml = (
            "Thanks for contacting CourseFinity Support! We have received your contact form enquiry and will respond back as soon as we are able to.",
            "For the fastest resolution to your enquiry, please provide the Support Team with as much information as possible and keep it contained to a this email instead of creating a new one.",
            f"While you are waiting, you can check our FAQ page at {current_app.config['CONSTANTS'].CUSTOM_DOMAIN}{url_for('generalBP.faq')} for solutions to common problems.",
            f"Below is a copy of your enquiry:<br>{enquiry}"
        )
        send_email(to=email, subject=enquiryType, body="<br><br>".join(bodyHtml), name=name)
        flash(
            Markup("Your enquiry has been submitted successfully!<br>We will get back to you shortly!"),
            "Enquiry Submitted!"
        )

    return render_template(
        "users/general/contact_us.html", accType=accType, imageSrcPath=imageSrcPath, form=contactUsForm
    )

@generalBP.route("/community-guidelines")
def communityGuidelines():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/community_guidelines.html", accType=accType, imageSrcPath=imageSrcPath)

@generalBP.route("/teacher-handbook")
def teacherHandBook():
    accType = imageSrcPath = None
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/teacher_handbook.html", accType=accType, imageSrcPath=imageSrcPath)