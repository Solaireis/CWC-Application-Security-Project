from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, Markup, abort, send_from_directory
from werkzeug.utils import secure_filename
from os import environ
from pathlib import Path
from requests import post as pyPost
from apscheduler.schedulers.background import BackgroundScheduler
from matplotlib import pyplot as plt
from dicebear import DOptions
import sqlite3
from datetime import datetime
# from python_files import Student, Teacher, Forms, Course
from python_files.IntegratedFunctions import *
from python_files.Forms import *

"""Web app configurations"""
# general Flask configurations
app = Flask(__name__)
app.config["SECRET_KEY"] = "a secret key" # for demonstration purposes, if deployed, change it to something more secure
scheduler = BackgroundScheduler()

# Maximum file size for uploading anything to the web app's server
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024 # 200MiB

# Configurations for dicebear api for user profile image options
app.config["DICEBEAR_OPTIONS"] = DOptions(
    size=250
)

# creating an absolute path for storing the shelve files
app.config["DATABASE_FOLDER"] = str(app.root_path) + "\\databases"

# for image uploads file path
app.config["PROFILE_UPLOAD_PATH"] = "static/images/user"
app.config["THUMBNAIL_UPLOAD_PATH"] = "static/images/courses/thumbnails"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ("png", "jpg", "jpeg")

# for course video uploads file path
app.config["COURSE_VIDEO_FOLDER"] = "static/course_videos"
app.config["ALLOWED_VIDEO_EXTENSIONS"] = (".mp4, .mov, .avi, .3gpp, .flv, .mpeg4, .flv, .webm, .mpegs, .wmv")

#Configuration of SQL
app.config["USER_DATABASE_SQL"] = app.config["DATABASE_FOLDER"] + "\\database.db"

"""End of Web app configurations"""

@app.route("/")
def home():
    """Home page"""
    return render_template("users/general/home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("users/guest/login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
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

        con = sqlite3.connect(app.config["USER_DATABASE_SQL"], timeout=5)
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS user (
            id PRIMARY KEY, 
            role TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE, 
            email TEXT NOT NULL UNIQUE, 
            password TEXT NOT NULL, 
            profile_image TEXT NOT NULL, 
            date_joined DATE NOT NULL
        )""")

        emailDupe = bool(cur.execute("SELECT * FROM user WHERE email=:email", {"email": emailInput}).fetchall())

        usernameDupes = bool(cur.execute("SELECT * FROM user WHERE username=:username", \
                                                                    {"username": usernameInput}).fetchall())

        if (not emailDupe and not usernameDupes):
            while (1):
                try:
                    # add to the sqlite3 database
                    userID = generate_id()
                    data = (userID, "student", usernameInput, emailInput, passwordInput, "/static/images/user/default.jpg", datetime.now().strftime("%Y-%m-%d"))
                    cmd = "INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?)"
                    cur.execute(cmd, data)
                    break
                except sqlite3.IntegrityError:
                    # if the userID is already taken in very rare case, try again
                    continue

        # commit the changes to the database
        con.commit()
        con.close()

        if (emailDupe or usernameDupes):
            return render_template("users/guest/signup.html", form=signupForm, email_duplicates=emailDupe, username_duplicates=usernameDupes)

        return redirect(url_for("home"))

    # post request but form inputs are not valid
    return render_template("users/guest/signup.html", form=signupForm)

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