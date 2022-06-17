# import third party libraries
from werkzeug.utils import secure_filename
import requests as req
from apscheduler.schedulers.background import BackgroundScheduler
from dicebear import DOptions
from argon2 import PasswordHasher as PH

# import flask libraries
from flask import Flask, render_template, request, redirect, url_for, session, flash, Markup, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# import local python libraries
from python_files.AppFunctions import *
from python_files.NormalFunctions import *
from python_files.Forms import *
from python_files.Errors import *

# import python standard libraries
import secrets
from datetime import datetime
from pathlib import Path

"""Web app configurations"""

# general Flask configurations
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret" # secrets.token_hex(32) # 32 bytes/256 bits
scheduler = BackgroundScheduler()

# rate limiter configuration using flask limiter
limiter = Limiter(app, key_func=get_remote_address, default_limits=["30 per second"])

# Maximum file size for uploading anything to the web app's server
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024 # 200MiB

# Configurations for dicebear api for user profile image options
app.config["DICEBEAR_OPTIONS"] = DOptions(
    size=250
)

# for image uploads file path
app.config["PROFILE_UPLOAD_PATH"] = r"static\images\user"
app.config["THUMBNAIL_UPLOAD_PATH"] = r"static\images\courses\thumbnails"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ("png", "jpg", "jpeg")

# for course video uploads file path
app.config["COURSE_VIDEO_FOLDER"] = r"static\course_videos"
app.config["ALLOWED_VIDEO_EXTENSIONS"] = (".mp4, .mov, .avi, .3gpp, .flv, .mpeg4, .flv, .webm, .mpegs, .wmv")

# database folder path
app.config["DATABASE_FOLDER"] = app.root_path + r"\databases"

# SQL database file path
app.config["SQL_DATABASE"] = app.config["DATABASE_FOLDER"] + r"\database.db"

# Session config
app.config["SESSION_EXPIRY_INTERVALS"] = 30 # 30 mins

"""End of Web app configurations"""

@app.before_first_request # called at the very first request to the web app
def before_first_request():
    # get ip address blacklist from a github repo or the saved file
    app.config["IP_ADDRESS_BLACKLIST"] = get_IP_address_blacklist() 

@app.before_request # called before each request to the application.
def before_request():
    if (get_remote_address() in app.config["IP_ADDRESS_BLACKLIST"]):
        abort(403)
    elif ("user" in session):
        if (not sql_operation(table="user", mode="verify_userID_existence", userID=session["user"])):
            # if user session is invalid as the user does not exist anymore
            sql_operation(table="session", mode="delete_session", sessionID=session["sid"])
            session.clear()
            return

        if (sql_operation(table="session", mode="if_session_exists", sessionID=session["sid"])):
            # if session exists
            if (not sql_operation(table="session", mode="check_if_valid", sessionID=session["sid"], userID=session["user"])):
                # if user session is expired or the userID does not match with the sessionID
                sql_operation(table="session", mode="delete_session", sessionID=session["sid"])
                session.clear()
                return

            # update session expiry time
            sql_operation(table="session", mode="update_session", sessionID=session["sid"])
            return
        else:
            # if session does not exist in the db
            session.clear()
            return

    elif ("admin" in session and not sql_operation(table="user", mode="verify_adminID_existence", adminID=session["admin"])):
        # if admin session is invalid as the admin does not exist anymore
        session.clear()

@app.after_request # called after each request to the application
def add_header(response):
    """
    Add headers to cache the rendered page for 10 minutes.
    
    Note that max-age is for the browser, s-maxage is for the CDN.
    It will be useful when the flask web app is deployed to a server.
    This helps to reduce loads on the flask webapp such that the server can handle more requests
    as it doesn't have to render the page again for each request to the application.
    """
    # it is commented out as we are still developing the web app and it is not yet ready to be hosted.
    # will be uncommented when the web app is ready to be hosted on firebase.
    # response.headers["Cache-Control"] = "public, max-age=600, s-maxage=600"
    return response

@app.route("/")
def home():
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses")
    threeHighlyRatedCourses = sql_operation(table="course", mode="get_3_highly_rated_courses")

    userPurchasedCourses = []
    imageSrcPath = None
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo[-1]

    return render_template("users/general/home.html", accType=session.get("role"), imageSrcPath=imageSrcPath,   
        userPurchasedCourses=userPurchasedCourses,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per second")
def login():
    if ("user" not in session):
        loginForm = CreateLoginForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/login.html", form=loginForm)

        if (request.method == "POST" and loginForm.validate()):
            emailInput = loginForm.email.data
            passwordInput = loginForm.password.data

            successfulLogin = False
            try:
                userInfo = sql_operation(table="user", mode="login", email=emailInput, password=passwordInput)
                successfulLogin = True
                sql_operation(table="login_attempts", mode="reset_user_attempts", userID=userInfo[0])
            except (IncorrectPwdError, EmailDoesNotExistError):
                try:
                    sql_operation(table="login_attempts", mode="add_attempt", email=emailInput)
                    flash("Please check your entries and try again!", "Danger")
                except (EmailDoesNotExistError):
                    flash("Please check your entries and try again!", "Danger")
                except (AccountLockedError):
                    print("Account locked")
                    flash("Too many failed login attempts, please try again later.", "Danger")
            except (AccountLockedError):
                print("Account locked")
                flash("Too many failed login attempts, please try again later.", "Danger")

            if (successfulLogin):
                # minimum requirement for a session ID:
                # https://owasp.deteact.com/cheat/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-length
                sessionID = generate_id() # using a 32 byte session ID

                sql_operation(table="session", mode="create_session", sessionID=sessionID, userID=userInfo[0])
                session["sid"] = sessionID
                session["user"] = userInfo[0]
                session["role"] = userInfo[1]
                print(f"Successful Login : email: {emailInput}, password: {passwordInput}")
                return redirect(url_for("home"))
            else:
                return render_template("users/guest/login.html", form=loginForm)
        else:
            return render_template("users/guest/login.html", form = loginForm)
    else:
        return redirect(url_for("home"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if ("user" not in session):
        signupForm = CreateSignUpForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/signup.html", form=signupForm)

        if (request.method == "POST" and signupForm.validate()):
            # POST request code below
            emailInput = signupForm.email.data
            usernameInput = signupForm.username.data
            passwordInput = signupForm.password.data
            confirmPasswordInput = signupForm.cfm_password.data

            # some checks on the password input
            if (passwordInput != confirmPasswordInput):
                flash("Passwords did not match!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (len(passwordInput) < 10):
                flash("Password must be at least 10 characters long!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (len(passwordInput) > 48):
                flash("Password cannot be more than 48 characters long!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
                flash("Password is too weak, please enter a stronger password!")
                return render_template("users/guest/signup.html", form=signupForm)

            passwordInput = PH().hash(passwordInput)
            print(f"username: {usernameInput}, email: {emailInput}, password: {passwordInput}")

            returnedVal = sql_operation(table="user", mode="signup", email=emailInput, username=usernameInput, password=passwordInput)

            if (isinstance(returnedVal, tuple)):
                emailDupe = returnedVal[0]
                usernameDupe = returnedVal[1]
                if (emailDupe and usernameDupe):
                    flash("Email and username already exists!")
                elif (emailDupe):
                    flash("Email already exists!")
                elif (usernameDupe):
                    flash("Username already exists!")
                return render_template("users/guest/signup.html", form=signupForm)

            session["user"] = returnedVal # i.e. successful signup, returned the user ID
            session["role"] = "Student"
            return redirect(url_for("home"))

        # post request but form inputs are not valid
        return render_template("users/guest/signup.html", form=signupForm)
    else:
        return redirect(url_for("home"))

@app.route("/logout")
def logout():
    if ("user" not in session):
        return redirect(url_for("login"))

    sql_operation(table="session", mode="delete_session", sessionID=session["sid"])
    session.clear()
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("home"))

@app.route("/payment-settings", methods=["GET", "POST"])
def paymentSettings():
    if ("user" not in session):
        return redirect(url_for("login"))

    try:
        cardExists = sql_operation(table="user", mode="check_card_if_exist", userID=session["user"], getCardInfo=True)
        print(cardExists)
    except (CardDoesNotExistError):
        cardExists = False

    paymentForm = CreateAddPaymentForm(request.form)

    # GET method codes below
    if (request.method == "GET"):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        
        cardName = cardNumber = cardExpiry = None
        if (cardExists):
            cardInfo = cardExists[0]
            cardName = cardInfo[0]
            cardNumber = cardInfo[1]
            cardExpiry = cardInfo[2]

        return render_template("users/loggedin/payment_settings.html", form=paymentForm, accType=userInfo[1], imageSrcPath=imageSrcPath, cardExists=cardExists, cardName=cardName, cardNo=cardNumber, cardExpiry=cardExpiry)

    # POST method codes below
    if (paymentForm.validate() and not cardExists):
        # POST request code below
        cardNumberInput = paymentForm.cardNo.data
        cardNameInput = paymentForm.cardName.data
        cardExpiryInput = paymentForm.cardExpiry.data

        sql_operation(table="user", mode="add_card", userID=session["user"], cardNo=cardNumberInput, cardName=cardNameInput, cardExpiry=cardExpiryInput)
        return redirect(url_for("paymentSettings"))

    # invalid form inputs or already has a card
    return redirect(url_for("paymentSettings"))

@app.post("/delete-payment")
def deletePayment():
    if ("user" not in session):
        return redirect(url_for("login"))

    cardExists = sql_operation(table="user", mode="check_card_if_exist", userID=session["user"])
    if (not cardExists):
        return redirect(url_for("paymentSettings"))

    sql_operation(table="user", mode="delete_card", userID=session["user"])
    return redirect(url_for("paymentSettings"))

@app.route("/edit-payment", methods=["GET", "POST"])
def editPayment():
    if ("user" not in session):
        return redirect(url_for("login"))

    cardExists = sql_operation(table="user", mode="check_card_if_exist", userID=session["user"], getCardInfo=True)
    if (not cardExists):
        return redirect(url_for("paymentSettings"))

    editPaymentForm = CreateEditPaymentForm(request.form)

    if (request.method == "GET"):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        cardInfo = cardExists[0]
        cardName = cardInfo[0]
        cardExpiry = cardInfo[2]

        return render_template("users/loggedin/edit_payment.html", form=editPaymentForm, accType=userInfo[1], imageSrcPath=imageSrcPath, cardName=cardName, cardExpiry=cardExpiry)

    if (editPaymentForm.validate()):
        # POST request code below
        cardExpiryInput = editPaymentForm.cardExpiry.data

        sql_operation(table="user", mode="update_card", userID=session["user"], cardExpiry=cardExpiryInput)
        return redirect(url_for("paymentSettings"))

    # invalid form inputs
    return redirect(url_for("paymentSettings"))

@app.route("/user_profile", methods=["GET","POST"])
def userProfile():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)

        username = userInfo[2]
        accType = userInfo[1]
        email = userInfo[3]

        return render_template("users/loggedin/user_profile.html", username=username, accType=accType, email=email, imageSrcPath=imageSrcPath)
    else:
        return redirect(url_for("login"))

@app.route("/change_username", methods=["GET","POST"])
def updateUsername():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]

        create_update_username_form = CreateChangeUsername(request.form)
        if (request.method == "POST") and (create_update_username_form.validate()):
            updatedUsername = create_update_username_form.updateUsername.data

            changed = False
            try:
                sql_operation(table="user", mode="change_username", userID=userID, username=updatedUsername)
                changed = True
                flash("Your username has been successfully changed.", "Account Details Updated!")
            except (ReusedUsernameError):
                flash("Sorry, Username has already been taken!")

            if (changed):
                return redirect(url_for("userProfile"))
            else:
                return render_template("users/loggedin/change_username.html", form=create_update_username_form, imageSrcPath=imageSrcPath)
        else:
            return render_template("users/loggedin/change_username.html", form=create_update_username_form, imageSrcPath=imageSrcPath)
    else:
        return redirect(url_for("login"))

@app.route("/change_email", methods=["GET","POST"])
def updateEmail():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]
        oldEmail = userInfo[2]

        create_update_email_form = CreateChangeEmail(request.form)
        if (request.method == "POST") and (create_update_email_form.validate()):
            updatedEmail = create_update_email_form.updateEmail.data
            currentPassword = create_update_email_form.currentPassword.data

            changed = False
            try:
                sql_operation(table="user", mode="change_email", userID=userID, email=updatedEmail, currentPassword=currentPassword)
                changed = True
            except (EmailAlreadyInUseError):
                flash("Sorry, email has already been taken!")
            except (SameAsOldEmailError):
                flash("Sorry, please enter a different email from your current one!")
            except (IncorrectPwdError):
                flash("Sorry, please check your current password and try again!")

            if (not changed):
                return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=imageSrcPath)
            else:
                print(f"old email:{oldEmail}, new email:{updatedEmail}")
                flash("Your email has been successfully changed.", "Account Details Updated!")
                return redirect(url_for("userProfile"))
        else:
            return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=imageSrcPath)
    else:
        return redirect(url_for("login"))

@app.route("/change_password", methods=["GET","POST"])
def updatePassword():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]

        create_update_password_form = CreateChangePasswordForm(request.form)
        if (request.method == "POST") and (create_update_password_form.validate()):
            currentPassword = create_update_password_form.currentPassword.data
            updatedPassword = create_update_password_form.updatePassword.data
            confirmPassword = create_update_password_form.confirmPassword.data

            if (updatedPassword != confirmPassword):
                flash("Passwords Do Not Match!")
                return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=imageSrcPath)
            else:
                changed = False
                try:
                    sql_operation(table="user", mode="change_password", userID=userID, password=updatedPassword, oldPassword=currentPassword)
                    changed = True
                except (ChangePwdError):
                    flash("Please check your entries and try again.")
                except (PwdTooShortError, PwdTooLongError):
                    flash("Password must be between 10 and 48 characters long.")
                except (PwdTooWeakError):
                    flash("Password is too weak, please enter a stronger password!")

                if (changed):
                    flash("Your password has been successfully changed.", "Account Details Updated!")
                    return redirect(url_for("userProfile"))
                else:
                    return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=imageSrcPath)
        else:
            return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=imageSrcPath)
    else:
        return redirect(url_for("login"))

@app.route("/change_account_type", methods=["GET","POST"])
def changeAccountType():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]
        if (request.method == "POST") and (request.form["changeAccountType"] == "changeToTeacher"):
            try:
                sql_operation(table="user", mode="update_to_teacher", userID=userID)
                flash("Your account has been successfully upgraded to a Teacher.", "Account Details Updated!")
            except (IsAlreadyTeacherError):
                flash("You are already a teacher!", "Failed to Update!")
            return redirect(url_for("userProfile"))
        else:
            print("Not POST request or did not have relevant hidden field.")
            return redirect(url_for("userProfile"))
    else:
        return redirect(url_for("login"))

@app.route("/upload_profile_pic" , methods=["GET","POST"])
def uploadPic():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]

        if (request.method == "POST"):
            if "profilePic" not in request.files:
                print("No File Sent")
                return redirect(url_for("userProfile"))

            file = request.files["profilePic"]
            filename = file.filename
            print(f"This is the filename for the inputted file : {filename}")

            filepath = Path(app.config["PROFILE_UPLOAD_PATH"]).joinpath(filename)
            # filepath = os.path.join(app.config["PROFILE_UPLOAD_PATH"], filename)
            print(f"This is the filepath for the inputted file: {filepath}")
            
            file.save(Path("src/Insecure/").joinpath(filepath))
            # file.save(os.path.join("src/Insecure/", filepath))

            sql_operation(table="user", mode="edit", userID=userID, profileImagePath=str(filepath), newAccType=False)

            return redirect(url_for("userProfile"))

        # if request is not post
        return redirect(url_for("userProfile"))
    else:
        return redirect(url_for("login"))

@app.route("/create_course", methods=["GET","POST"])
def createCourse():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]
        accType = userInfo[1]
        courseForm = CreateCourse(request.form)
        if (request.method == "POST"):
            courseTitle = courseForm.courseTitle.data
            courseDescription = courseForm.courseDescription.data
            courseTagInput = request.form.get("courseTag")
            coursePrice = float(courseForm.coursePrice.data)

            file = request.files.get("courseThumbnail")
            filename = file.filename

            print(f"This is the filename for the inputted file : {filename}")

            filepath = Path(app.config["THUMBNAIL_UPLOAD_PATH"]).joinpath(filename)
            # filepath = os.path.join(app.config["PROFILE_UPLOAD_PATH"], filename)
            print(f"This is the filepath for the inputted file: {filepath}")
            
            file.save(Path("src/Insecure/").joinpath(filepath))

            if (request.files["courseVideo"].filename == ""):
                flash("Please Upload a Video Or Link")
                return redirect(url_for("createCourse"))


            file = request.files.get("courseVideo")
            filename = file.filename
            filepath = Path(app.config["COURSE_VIDEO_FOLDER"]).joinpath(filename)
            # filepath = os.path.join(app.config["PROFILE_UPLOAD_PATH"], filename)
            print(f"This is the filepath for the inputted file: {filepath}")

            file.save(Path("src/Insecure/").joinpath(filepath))

            # imageResized, webpFilePath = resize_image(newFilePath, (1920, 1080))

            sql_operation(table="course", mode="insert",teacherId=userID, courseName=courseTitle, courseDescription=courseDescription, courseImagePath=filename, courseCategory=courseTagInput, coursePrice=coursePrice, videoPath=filename)

            return redirect(url_for("home"))
        else:
            return render_template("users/teacher/create_course.html", accType=accType, imageSrcPath=imageSrcPath, form = courseForm)
    else:
        return redirect(url_for("login"))

@app.route("/teacher/<teacherID>")
def teacherPage(teacherID):
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", teacherID=teacherID, getTeacherUsername=False)
    threeHighlyRatedCourses, teacherUsername = sql_operation(table="course", mode="get_3_highly_rated_courses", teacherID=teacherID, getTeacherUsername=True)

    teacherProfilePath = get_image_path(teacherID)

    imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath = get_image_path(session["user"])
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])

    return render_template("users/general/teacher_page.html", accType=session.get("role"),                              
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherUsername=teacherUsername, 
        teacherProfilePath=teacherProfilePath,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses))

@app.route("/course/<courseID>")
def coursePage(courseID):
    print(courseID)
    #courseID = "a78da127690d40d4bebaf5d9c45a09a8"
    # the course id is 
    #   a78da127690d40d4bebaf5d9c45a09a8
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    #courseName = courses[0][1]
    print(courses)
    if courses == False: #raise exception
        abort(404)
    #create variable to store these values
    teacherID = courses[1]
    courseName = courses[2]
    courseDescription = courses[3]
    coursePrice = courses[5]
    courseCategory = courses[6]
    courseRating = courses[7]
    courseRatingCount = courses[8]
    courseDate = courses[9]
    courseVideoPath = courses[10]

    print("course",courses[1])

    teacherProfilePath = get_image_path(teacherID)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=teacherID, )
    print(teacherRecords)
    teacherName = teacherRecords[2]


    imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath = get_image_path(session["user"])
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])

    return render_template("users/general/course_page.html", accType=session.get("role"),
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherName, teacherProfilePath=teacherProfilePath \
        , courseID=courseID, courseName=courseName, courseDescription=courseDescription, coursePrice=coursePrice, courseCategory=courseCategory, \
        courseRating=courseRating, courseRatingCount=courseRatingCount, courseDate=courseDate, courseVideoPath=courseVideoPath)

@app.route("/course-review/<courseID>")
def courseReview(courseID):
    imageSrcPath = None
    userPurchasedCourses = {}
    courses = sql_operation(table="course", mode="", courseID=courseID)
    
    if ("user" in session):
        imageSrcPath = get_image_path(session["user"])
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])

    return render_template("users/general/course_page_review.html", accType=session.get("role"),
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, courseID=courseID)

@app.route("/purchase-view/<courseID>")
def purchaseView(courseID):
    print(courseID)
    #courseID = "a78da127690d40d4bebaf5d9c45a09a8"
    # the course id is 
    #   a78da127690d40d4bebaf5d9c45a09a8
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    #courseName = courses[0][1]
    if courses == False: #raise 404 error
        abort(404)

    #create variable to store these values
    teacherID = courses[1]
    courseName = courses[2]
    courseDescription = courses[3]
    coursePrice = courses[5]
    courseCategory = courses[6]
    courseRating = courses[7]
    courseRatingCount = courses[8]
    courseDate = courses[9]
    courseVideoPath = courses[10]

    print("course",courses[1])

    teacherProfilePath = get_image_path(teacherID)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=teacherID, )
    print(teacherRecords)
    teacherName = teacherRecords[2]


    imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath = get_image_path(session["user"])
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])

    return render_template("users/general/purchase_view.html", accType=session.get("role"),
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherName, teacherProfilePath=teacherProfilePath \
        , courseID=courseID, courseName=courseName, courseDescription=courseDescription, coursePrice=coursePrice, courseCategory=courseCategory, \
        courseRating=courseRating, courseRatingCount=courseRatingCount, courseDate=courseDate, courseVideoPath=courseVideoPath)
        

@app.post("/add_to_cart/<courseID>")
def addToCart(courseID):
    if ("user" in session):
        sql_operation(table = "user", mode = "add_to_cart", userID = session["user"], courseID = courseID)
        return redirect(url_for("cart"))
    else:
        return redirect(url_for("login"))

@app.route("/shopping_cart", methods=["GET", "POST"])
def cart():
    if "user" in session:
        
        if request.method == "POST":
            # Remove item from cart
            courseID = request.form.get("courseID")
            sql_operation(table = "user", mode = "remove_from_cart", userID = session["user"], courseID = courseID)

            return redirect(url_for("cart"))

        else:

            cartCourseIDs = sql_operation(table = "user", mode = "get_user_cart", userID = session["user"])
            # print(cartCourseIDs)
            
            courseList = []
            subtotal = 0

            for courseID in cartCourseIDs:
                
                course = sql_operation(table = "course", mode = "get_course_data", courseID = courseID)

                courseList.append({"courseID" : course[0],
                                   "courseOwnerLink" : url_for("teacherPage", teacherID=course[1]), # course[1] is teacherID
                                   "courseOwnerUsername" : sql_operation(table = "user", mode = "get_user_data", userID = course[1])[2],
                                   "courseOwnerImagePath" : get_image_path(course[1]),
                                   "courseName" : course[2],
                                   "courseDescription" : course[3],
                                   "courseThumbnailPath" : course[4],
                                   "coursePrice" : f"{course[5]:,.2f}",
                                 })

                subtotal += course[5]

            return render_template("users/loggedin/shopping_cart.html", courseList = courseList, subtotal = f"{subtotal:,.2f}", imageSrcPath = get_image_path(session["user"]))

    else:
        return redirect(url_for("login"))

@app.route("/checkout", methods = ["GET", "POST"])
def checkout():
    if "user" in session:

        if request.method == "POST":

            cardNo = request.form.get("cardNo")
            cardExpiryMonth  = request.form.get('cardExpMonth')
            cardExpiryYear = request.form.get('cardExpYear')
            cardCVV = request.form.get("cardCVV")
            cardName = request.form.get("cardName")
            cardSave = request.form.get("cardSave")
            print(cardCVV)

            cardErrors = []

            if cardNo == "":
                cardErrors.append('cardNo')
            if cardExpiryMonth == "":
                cardErrors.append('cardExpiryMonth')
            if cardExpiryYear == "":
                cardErrors.append('cardExpiryYear')
            if cardCVV == "":
                cardErrors.append('cardCVV')
            if cardName == "":
                cardErrors.append('cardName')

            session['cardErrors'] = cardErrors

            cardExpiry = f"{cardExpiryMonth}-{cardExpiryYear}"

            print(cardExpiryMonth)
            print(cardExpiryYear)

            # Errors, try again.
            if cardErrors != []:
                return redirect(url_for("checkout"))

            else:

                if cardSave != None:
                    sql_operation(table = "user", mode = "edit", userID = session["user"], cardNo = cardNo, cardExpiry = cardExpiry, cardCVV = cardCVV, cardName = cardName)

                # Make Purchase
                # sql_operation(table = "user", mode = "purchase_courses", userID = session["user"])

                return redirect(url_for("purchaseHistory"))

        else:

            userInfo = sql_operation(table = "user", mode = "get_user_data", userID = session["user"])

            cardInfo = {"cardName": "",
                        "cardNo": "",
                        "cardExpMonth": "",
                        "cardExpYear": "",
                        "cardCVV": ""
                        }

            if userInfo[7] is not None:

                cardInfo["cardName"] = userInfo[7]
                cardInfo["cardNo"] = userInfo[8]
                cardInfo["cardExpMonth"] = int(userInfo[9].split("-")[0])
                cardInfo["cardExpYear"] = int(userInfo[9].split("-")[1])
                cardInfo["cardCVV"] = userInfo[10]

            cartCourseIDs = sql_operation(table = "user", mode = "get_user_cart", userID = session["user"])
            cartCount = len(cartCourseIDs)

            subtotal = 0

            for courseID in cartCourseIDs:
                course = sql_operation(table = "course", mode = "get_course_data", courseID = courseID)
                subtotal += course[5]

            currentYear = datetime.today().year

            if 'cardErrors' not in session:
                cardErrors = []
            else:
                cardErrors = session['cardErrors']

            print(cardErrors)

            return render_template("users/loggedin/checkout.html", cardErrors = cardErrors , cartCount = cartCount, subtotal = f"{subtotal:,.2f}", cardInfo = cardInfo, currentYear = currentYear, imageSrcPath = get_image_path(session["user"]))

    else:
        return redirect(url_for("login"))

@app.route("/purchase_history")
def purchaseHistory():
    purchasedCourseIDs = sql_operation(table = "user", mode = "get_user_purchases", userID = session["user"])
    courseList = []
    
    for courseID in purchasedCourseIDs:
    
        course = sql_operation(table = "course", mode = "get_course_data", courseID = courseID)
    
        courseList.append({"courseID" : course[0],
                            "courseOwnerLink" : url_for("teacherPage", teacherID=course[1]), # course[1] is teacherID
                            "courseOwnerUsername" : sql_operation(table = "user", mode = "get_user_data", userID = course[1])[2],
                            "courseOwnerImagePath" : get_image_path(course[1]),
                            "courseName" : course[2],
                            "courseDescription" : course[3],
                            "courseThumbnailPath" : course[4],
                            "coursePrice" : f"{course[5]:,.2f}",
                            })

    return render_template("users/loggedin/purchase_history.html", courseList = courseList, imageSrcPath = get_image_path(session["user"]))

@app.route("/purchase-view/<courseID>")
def purchaseDetails(courseID):

    return render_template("users/loggedin/purchase_view.html", courseID = courseID)

@app.route("/search", methods=["GET","POST"])
def search():
    searchInput = str(request.args.get("q"))
    foundResults = sql_operation(table="course", mode="search", searchInput=searchInput)
    if ("user" in session):
        imageSrcPath = get_image_path(session["user"]) 
        return render_template("users/general/search.html", searchInput=searchInput, foundResults=foundResults, foundResultsLen=len(foundResults), imageSrcPath=imageSrcPath)
    return render_template("users/general/search.html", searchInput=searchInput, foundResults=foundResults, foundResultsLen=len(foundResults))

@app.route("/admin-profile", methods=["GET","POST"])
def adminProfile():
    if ("admin" in session):
        imageSrcPath, userInfo = get_image_path(session["admin"], returnUserInfo=True)
        userID = userInfo[0]
        userUsername = userInfo[1]
        userEmail = userInfo[2]
        userAccType = userInfo[3]

        return render_template("users/admin/admin_profile.html", imageSrcPath=imageSrcPath, userUsername=userUsername, userEmail=userEmail, userAccType=userAccType, userID=userID)
    
    # for logged users that are not admins
    if ("user" in session):
        return redirect(url_for("userProfile"))

    # for guests
    return redirect(url_for("login"))

@app.route("/admin-dashboard", methods=["GET","POST"])
def adminDashboard():
    pass

@app.route("/teapot")
def teapot():
    abort(418)

"""Custom Error Pages"""

# Bad Request
@app.errorhandler(400)
def error400(e):
    return render_template("errors/401.html"), 400

# Unauthorised
@app.errorhandler(401)
def error401(e):
    return render_template("errors/401.html"), 401

# Forbidden
@app.errorhandler(403)
def error403(e):
    return render_template("errors/403.html"), 403

# Not Found
@app.errorhandler(404)
def error404(e):
    return render_template("errors/404.html"), 404

# Method Not Allowed
@app.errorhandler(405)
def error405(e):
    return render_template("errors/405.html"), 405

# Payload Too Large
@app.errorhandler(413)
def error413(e):
    return render_template("errors/413.html"), 413

# I'm a Teapot
@app.errorhandler(418)
def error418(e):
    return render_template("errors/418.html"), 418

# Too Many Requests
@app.errorhandler(429)
def error429(e):
    return render_template("errors/429.html"), 429

# Internal Server Error
@app.errorhandler(500)
def error500(e):
    return render_template("errors/500.html"), 500

# Not Implemented
@app.errorhandler(501)
def error501(e):
    return render_template("errors/501.html"), 501

# Bad Gateway
@app.errorhandler(502)
def error502(e):
    return render_template("errors/502.html"), 502

# Service Temporarily Unavailable
@app.errorhandler(503)
def error503(e):
    return render_template("errors/503.html"), 503

"""End of Custom Error Pages"""

if (__name__ == "__main__"):
    scheduler.configure(timezone="Asia/Singapore") # configure timezone to always follow Singapore's timezone
    scheduler.add_job(lambda: sql_operation(table="session", mode="delete_expired_sessions"), trigger="cron", hour="23", minute="58", second="0", id="deleteExpiredSessions")
    scheduler.add_job(lambda: sql_operation(table="login_attempts", mode="reset_attempts_past_reset_date"), trigger="cron", hour="23", minute="59", second="0", id="resetLockedAccounts")
    scheduler.start()
    app.run(debug=True)
    # app.run(debug=True, use_reloader=False)