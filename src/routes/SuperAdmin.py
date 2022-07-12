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

@superAdminBP.route("/admin-dashboard/admin-management", methods=["GET","POST"])
def adminManagement():
    admins= sql_operation(table="role", mode="retrieve_admin")
    

    # # Pagination starts below
    # pageNum = request.args.get("p", default=1, type=int)
    # userInput = request.args.get("user", default=None, type=str)
    # userInput = quote_plus(userInput) if (userInput is not None) else None
    # if (userInput is not None):
    #     filterInput = request.args.get("filter", default="username", type=str)
    #     if (filterInput not in ("username", "uid", "email")):
    #         filterInput = "username"

    #     userInput = userInput[:100] # limit user input to 100 characters to avoid buffer overflow when querying in MySQL
    #     userArr, maxPage = sql_operation(table="user", mode="paginate_users", pageNum=pageNum, user=unquote_plus(userInput), filterType=filterInput)
    # else:
    #     userArr, maxPage = sql_operation(table="user", mode="paginate_users", pageNum=pageNum)

    # if (pageNum > maxPage):
    #     if (userInput is not None):
    #         return redirect(f"{url_for('adminBP.userManagement')}?user={userInput}&filter={filterInput}&p={maxPage}")
    #     else:
    #         return redirect(f"{url_for('adminBP.userManagement')}?p={maxPage}")
    # elif (pageNum < 1):
    #     if (userInput is not None):
    #         return redirect(f"{url_for('adminBP.userManagement')}?user={userInput}&filter={filterInput}&p=1")
    #     else:
    #         return redirect(f"{url_for('adminBP.userManagement')}?p=1")

    # # Compute the buttons needed for pagination
    # paginationArr = get_pagination_arr(pageNum=pageNum, maxPage=maxPage)

    # # save the current URL in the session for when the admin searches and an error occurs
    # session["relative_url"] = request.full_path
    # return render_template("users/admin/user_management.html", currentPage=pageNum, userArr=userArr, maxPage=maxPage, paginationArr=paginationArr, form=recoverUserForm)
    return admins

@superAdminBP.route("/admin-dashboard/rbac", methods=["GET","POST"])
def roleManagement():
    roles = sql_operation(table="role", mode="retrieve_all")
    roleList = []
    for roleID in roles:
        roleList.append(RoleInfo(roleID))
        
    return 

