"""
Support file access (specifically send_from_directory)
"""

# import flask libraries (Third-party libraries)
from flask import Blueprint, send_from_directory, current_app, request

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *

filesBP = Blueprint("filesBP", __name__, static_folder="static", template_folder="template")

@filesBP.route('/static/course_videos/<string:courseID>.mpd')
def get_course_mpd_file(courseID):
    return send_from_directory(f"{current_app.root}/static", filename=f'course_videos/{courseID}.mpd')

@filesBP.route('/test')
def test():
    pass