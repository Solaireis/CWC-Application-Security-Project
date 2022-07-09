"""
Routes for admin users
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, redirect, url_for, session, request
from urllib.parse import quote_plus

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Forms import *

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
    pageNum = request.args.get("p", default=1, type=int)

    userInput = request.args.get("user", default=None, type=str)
    if (userInput is not None):
        filterInput = request.args.get("filter", default="username", type=str)
        if (filterInput not in ("username", "uid", "email")):
            filterInput = "username"

        userInput = userInput[:100] # limit user input to 100 characters to avoid buffer overflow when querying in MySQL
        userArr, maxPage = sql_operation(table="user", mode="paginate_users", pageNum=pageNum, user=userInput, filterType=filterInput)
    else:
        userArr, maxPage = sql_operation(table="user", mode="paginate_users", pageNum=pageNum)

    if (pageNum > maxPage):
        if (userInput is not None):
            userInput = quote_plus(userInput)
            filterInput = quote_plus(filterInput)
            return redirect(f"{url_for('adminBP.userManagement')}?user={userInput}&filter={filterInput}&p={maxPage}")
        else:
            return redirect(f"{url_for('adminBP.userManagement')}?p={maxPage}")
    elif (pageNum < 1):
        if (userInput is not None):
            userInput = quote_plus(userInput)
            filterInput = quote_plus(filterInput)
            return redirect(f"{url_for('adminBP.userManagement')}?user={userInput}&filter={filterInput}&p=1")
        else:
            return redirect(f"{url_for('adminBP.userManagement')}?p=1")

    paginationArr = get_pagination_arr(pageNum=pageNum, maxPage=maxPage)

    recoverUserForm = AdminRecoverForm(request.form)

    return render_template("users/admin/user_management.html", currentPage=pageNum, userArr=userArr, maxPage=maxPage, paginationArr=paginationArr, form=recoverUserForm)