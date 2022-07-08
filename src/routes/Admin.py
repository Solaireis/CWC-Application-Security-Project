"""
Routes for admin users
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, redirect, url_for, session
from requests import request

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *

adminBP = Blueprint("adminBP", __name__, static_folder="static", template_folder="template")

@adminBP.route("/admin-profile")
def adminProfile():
    userInfo = sql_operation(table="user", mode="get_user_data", userID=session["admin"])
    adminID = userInfo[0]
    adminUsername = userInfo[2]
    adminEmail = userInfo[3]

    return render_template("users/admin/admin_profile.html", username=adminUsername, email=adminEmail, adminID=adminID, accType=userInfo[1])

@adminBP.route("/user-management", methods=["GET","POST"])
def userManagement():
    pageNum = request.args.get("page", default=1, type=int)
    return render_template("users/admin/user_management.html", pageNum=pageNum)