"""
Routes for admin users
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, redirect, url_for, session

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Roles import RoleInfo

superAdminBP = Blueprint("superAdminBP", __name__, static_folder="static", template_folder="template")

@superAdminBP.route("/admin-dashboard", methods=["GET","POST"])
def adminDashboard():
    roles= sql_operation(table="review", mode="retrieve_all")
    roleList = []
    for roleID in roles:
        roleList.append(RoleInfo(roleID))

    return 

