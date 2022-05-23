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
app.config["SQL_DATABASE"] = app.root_path + "\\databases\\database.db"

"""End of Web app configurations"""

@app.route("/")
def home():
    imageSrcPath = None
    if ("user" in session):
        userInfo = user_sql_operation(mode="get_user_data", userID=session["user"])
        print(userInfo)
        imageSrcPath = userInfo[5]
        print("Image Source Path:", imageSrcPath)
        if (not imageSrcPath):
            imageSrcPath = get_dicebear_image(userInfo[2])

    return render_template("users/general/home.html", accType=session.get("role"), imageSrcPath=imageSrcPath)

@app.route("/login", methods=["GET", "POST"])
def login():
    if ("user" not in session):
        loginForm = CreateLoginForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/login.html", form=loginForm)

        if (request.method == "POST" and loginForm.validate()):
            emailInput = loginForm.email.data
            passwordInput = loginForm.password.data

            successfulLogin = user_sql_operation(mode="login", email=emailInput, password=passwordInput)
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

            returnedVal = user_sql_operation(mode="insert", email=emailInput, username=usernameInput, password=passwordInput)

            if (isinstance(returnedVal, tuple)):
                return render_template("users/guest/signup.html", form=signupForm, email_duplicates=returnedVal[0], username_duplicates=returnedVal[1])

            session["user"] = returnedVal # i.e. successful signup, returned the user ID
            session["role"] = "Student"
            return redirect(url_for("home"))

        # post request but form inputs are not valid
        return render_template("users/guest/signup.html", form=signupForm)
    else:
        return redirect(url_for("home"))

@app.route('/logout')
def logout():
    if ("user" in session):
        session.clear()
    else:
        return redirect(url_for("home"))
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("home"))

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