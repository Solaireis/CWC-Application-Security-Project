from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, Markup, abort, send_from_directory
from werkzeug.utils import secure_filename
from os import environ
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path
from requests import post as pyPost
from apscheduler.schedulers.background import BackgroundScheduler
from matplotlib import pyplot as plt
from dicebear import DOptions
from python_files import Student, Teacher, Forms, Course
from python_files.IntegratedFunctions import *

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

# Flask limiter configuration
limiter = Limiter(app, key_func=get_remote_address, default_limits=["30 per second"])

"""End of Web app configurations"""

@app.route("/")
def home():
    """Home page"""
    return render_template("users/general/home.html")


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
    app.run(debug=True, use_reloader=False)
