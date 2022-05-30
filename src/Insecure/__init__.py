from click import confirm
from flask import Flask, render_template, request, redirect, url_for, session, flash, Markup, abort
# from werkzeug.utils import secure_filename
from os import environ
from pathlib import Path
import requests as req
from apscheduler.schedulers.background import BackgroundScheduler
from dicebear import DOptions
from datetime import datetime
# from python_files import Student, Teacher, Forms, Course
from python_files.IntegratedFunctions import *
from python_files.Forms import *

"""

Task Allocation:
Jason - Payment Setting
Calvin - User Profile, course video upload, search for courses
Eden - Admin Profile, Review feature, Course Page (overview of the course details with a review section at the bottom)
Wei Ren - Shopping Cart, checkout, purchase history

Done alr
- Home
- Login
- Sign up
- Teacher Page (Same as home page, can copy the html code from the home.html)

"""

"""Web app configurations"""
# general Flask configurations
app = Flask(__name__)
app.config["SECRET_KEY"] = "a secret key"
scheduler = BackgroundScheduler()

# Maximum file size for uploading anything to the web app's server
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024 # 200MiB

# Configurations for dicebear api for user profile image options
app.config["DICEBEAR_OPTIONS"] = DOptions(
    size=250
)

# for image uploads file path
app.config["PROFILE_UPLOAD_PATH"] = "static/images/user"
app.config["THUMBNAIL_UPLOAD_PATH"] = "static/images/courses/thumbnails"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ("png", "jpg", "jpeg")

# for course video uploads file path
app.config["COURSE_VIDEO_FOLDER"] = "static/course_videos"
app.config["ALLOWED_VIDEO_EXTENSIONS"] = (".mp4, .mov, .avi, .3gpp, .flv, .mpeg4, .flv, .webm, .mpegs, .wmv")

# SQL database file path
app.config["SQL_DATABASE"] = app.root_path + "/databases/database.db"

"""End of Web app configurations"""

@app.before_request # called before each request to the application.
def before_request():
    if ("user" in session and not sql_operation(table="user", mode="verify_userID_existence", userID=session["user"])):
        # if user session is invalid as the user does not exist anymore
        session.clear()
    elif ("admin" in session and not sql_operation(table="user", mode="verify_adminID_existence", adminID=session["admin"])):
        # if admin session is invalid as the admin does not exist anymore
        session.clear()

@app.route("/")
def home():
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses")
    threeHighlyRatedCourses = sql_operation(table="course", mode="get_3_highly_rated_courses")

    userPurchasedCourses = []
    imageSrcPath = None
    if ("user" in session):
        imageSrcPath = get_image_path(session["user"])
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])

    return render_template("users/general/home.html", accType=session.get("role"), imageSrcPath=imageSrcPath,   
        userPurchasedCourses=userPurchasedCourses,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses))

@app.route("/login", methods=["GET", "POST"])
def login():
    if ("user" not in session):
        loginForm = CreateLoginForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/login.html", form=loginForm)

        if (request.method == "POST" and loginForm.validate()):
            emailInput = loginForm.email.data
            passwordInput = loginForm.password.data

            successfulLogin = sql_operation(table="user", mode="login", email=emailInput, password=passwordInput)
            print("successfulLogin: ", successfulLogin)
            if (successfulLogin):
                session["user"] = successfulLogin[0]
                session["role"] = successfulLogin[1]
                print(f"Successful Login : email: {emailInput}, password: {passwordInput}")
                return redirect(url_for("home"))
            else:
                flash("Please check your entries and try again!", "Danger")
                return render_template("users/guest/login.html", form=loginForm)

        # post request but form inputs are not valid
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
            if (passwordInput != confirmPasswordInput):
                return render_template("users/guest/signup.html", form=signupForm, pwd_were_not_matched=True)

            print(f"username: {usernameInput}, email: {emailInput}, password: {passwordInput}")

            returnedVal = sql_operation(table="user", mode="insert", email=emailInput, username=usernameInput, password=passwordInput)

            if (isinstance(returnedVal, tuple)):
                return render_template("users/guest/signup.html", form=signupForm, email_duplicates=returnedVal[0], username_duplicates=returnedVal[1])

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

    session.clear()
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("home"))

@app.route('/user_profile', methods=["GET","POST"])
def userProfile():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)

        username = userInfo[2]
        accType = userInfo[1]
        email = userInfo[3]

        return render_template("users/loggedin/user_profile.html", username=username, accType=accType, email=email, imageSrcPath=imageSrcPath)

@app.route('/change_username', methods=['GET','POST'])
def updateUsername():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]

        create_update_username_form = CreateChangeUsername(request.form)
        if (request.method == "POST") and (create_update_username_form.validate()):
            updatedUsername = create_update_username_form.updateUsername.data
        
            changed = sql_operation(table="user", mode="edit", userID=userID, username=updatedUsername)

            if (not changed):
                flash("Sorry, Username has already been taken!")
                return render_template('users/loggedin/change_username.html', form=create_update_username_form, imageSrcPath=imageSrcPath)
            
            else:
                return redirect(url_for("userProfile"))
        
        else:
            return render_template('users/loggedin/change_username.html', form=create_update_username_form, imageSrcPath=imageSrcPath)

@app.route('/change_email', methods=['GET','POST'])
def updateEmail():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]
        oldEmail = userInfo[2]

        create_update_email_form = CreateChangeEmail(request.form)
        if (request.method == "POST") and (create_update_email_form.validate()):
            updatedEmail = create_update_email_form.updateEmail.data
        
            changed = sql_operation(table="user", mode="edit", userID=userID, email=updatedEmail)

            if (not changed):
                flash("Sorry, Email is been used by another user!")
                return render_template('users/loggedin/change_email.html', form=create_update_email_form, imageSrcPath=imageSrcPath)
            
            else:
                print(f"old email:{oldEmail}, new email:{updatedEmail}")
                return redirect(url_for("userProfile"))
        
        else:
            return render_template('users/loggedin/change_email.html', form=create_update_email_form, imageSrcPath=imageSrcPath)

@app.route('/change_password', methods=['GET','POST'])
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
                flash("Passwords Do Not Match")
                return render_template('users/loggedin/change_password.html', form=create_update_password_form, imageSrcPath=imageSrcPath)
            else:
                changed = sql_operation(table="user", mode="edit", userID=userID, password=updatedPassword, oldPassword=currentPassword)

                if (changed):
                    flash(changed)
                    return render_template('users/loggedin/change_password.html', form=create_update_password_form, imageSrcPath=imageSrcPath)
                else:
                    return redirect(url_for("userProfile"))
        
        else:
            return render_template('users/loggedin/change_password.html', form=create_update_password_form, imageSrcPath=imageSrcPath)

@app.route('/change_account_type', methods=['GET','POST'])
def changeAccountType():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]
        if (request.method == "POST") and (request.form["changeAccountType"] == "changeToTeacher"):
            sql_operation(table="user", mode="edit", userID=userID, newAccType=True)
            return redirect(url_for("userProfile"))
        else:
            print("Not POST request or did not have relevant hidden field.")
            return redirect(url_for("userProfile"))

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
    courses = sql_operation(table="course", mode="get_course_by_id", courseID=courseID)
    # integrated function containing all sql 
    # use course.py represent tuple as an object 
    #retrieve one course id 
    #make it an course object
    # SELECT  course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course where course_id='123123123'
    if (len(courses) == 0):
        return redirect(url_for("homePage"))
    else:
        return render_template("users/general/course_page.html", accType=session.get("role"), course_ID=course_ID)

@app.route("/cart", methods=["GET", "POST"])
def cart():
    if request.method == "POST":
        # add to cart
        courseID = request.form.get("courseID")

    else:
        pass

    return "cart"

@app.route("/purchase-history")
def purchaseHistory():
    return "purchase history"

@app.route("/my-purchase?id=<courseID>")
def purchaseDetails(courseID):
    return "purchase details: " + courseID

@app.route('/search', methods=["GET","POST"])
def search():
    searchInput = str(request.args.get("q"))
    foundResults = sql_operation(table="course", mode="search", searchInput=searchInput)
    return render_template("users/general/search.html", searchInput=searchInput, foundResults=foundResults, foundResultsLen=len(foundResults))

@app.route('/admin-profile', methods=["GET","POST"])
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

if __name__ == '__main__':
    app.run(debug=True)