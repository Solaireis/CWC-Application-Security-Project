"""
Routes for admin users
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, redirect, url_for, session, request, current_app

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Roles import RoleInfo
from python_files.classes.Forms import *

# import python standard libraries
from urllib.parse import quote_plus, unquote_plus

superAdminBP = Blueprint("superAdminBP", __name__, static_folder="static", template_folder="template")

@superAdminBP.route("/admin-management", methods=["GET","POST"])
def adminManagement():
    pageNum = request.args.get("p", default=1, type=int)
    if (pageNum < 1):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].NEGATIVE_PAGE_NUM_REGEX, "p=1", request.url, count=1)
        )

    recoverUserForm = AdminRecoverForm(request.form)
    # Form actions starts below
    if (request.method == "POST"):
        userID = request.form.get("uid", default=None, type=str)
        formType = request.form.get("formType", default=None, type=str)
        if (userID is None or formType is None):
            flash("No account ID or form type was provided upon submission of form.", "Error")
            return redirect(session["relative_url"])

        userInfo = sql_operation(table="user", mode="get_user_data", userID=userID)
        if (userInfo is None):
            flash("No user account was found with the provided ID.", "No Such User!")
            return redirect(session["relative_url"])

        if (userInfo.role == "SuperAdmin"):
            flash("An error occurred while processing your request.", "Sorry!")
            return redirect(session["relative_url"])

        elif (formType == "deleteUser"):
            sql_operation(table="user", mode="delete_user", userID=userID)
            flash(f"The user, {userID}, has been deleted.", "User Deleted!")

        elif (formType == "changeUsername"):
            newUsername = request.form.get("newUsername", default=None, type=str)
            if (newUsername is None):
                flash("No new username was provided upon submission of form.", "Error")
            else:
                try:
                    sql_operation(table="user", mode="change_username", userID=userID, username=newUsername)
                    flash(f"The user, {userID}, has its username changed to {newUsername}.", "User's Account Details Updated!")
                except (ReusedUsernameError):
                    flash("The new username entered is already in use...", "Error changing user's username!")

        elif (formType == "resetProfileImage" and userInfo.hasProfilePic and "https://storage.googleapis.com/coursefinity" in userInfo.profileImage):
            sql_operation(table="user", mode="delete_profile_picture", userID=userID)
            flash(f"The user, {userID}, has its profile picture reset.", "User's Account Details Updated!")

        elif (formType == "banUser" and userInfo.status != "Banned"):
            sql_operation(table="user", mode="ban_user", userID=userID)
            flash(f"The user, {userID}, has been banned.", "User's Account Details Updated!")

        elif (formType == "unbanUser" and userInfo.status == "Banned"):
            sql_operation(table="user", mode="unban_user", userID=userID)
            flash(f"The user, {userID}, has been unbanned.", "User's Account Details Updated!")

        else:
            flash("An error occurred while processing your request.", "Sorry!")

        return redirect(session["relative_url"])

    userInput = request.args.get("user", default=None, type=str)
    userInput = quote_plus(userInput) if (userInput is not None) else None
    if (userInput is not None):
        filterInput = request.args.get("filter", default="username", type=str)
        if (filterInput not in ("username", "uid", "email")):
            filterInput = "username"

        userInput = userInput[:100] # limit user input to 100 characters to avoid buffer overflow when querying in MySQL
        userArr, maxPage = sql_operation(
            table="user", mode="paginate_users", pageNum=pageNum, 
            userInput=unquote_plus(userInput), filterType=filterInput, role="Admin"
        )
    else:
        # print(sql_operation(table="user", mode="paginate_users", pageNum=pageNum, role="Admin"))
        userArr, maxPage = sql_operation(table="user", mode="paginate_users", pageNum=pageNum, role="Admin")

    if (pageNum > maxPage):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].PAGE_NUM_REGEX, f"p={maxPage}", request.url, count=1)
        )

    # Compute the buttons needed for pagination
    paginationArr = get_pagination_arr(pageNum=pageNum, maxPage=maxPage)

    # save the current URL in the session for when the admin searches and an error occurs
    session["relative_url"] = request.full_path
    return render_template("users/superadmin/admin_management.html", currentPage=pageNum, userArr=userArr, maxPage=maxPage, paginationArr=paginationArr, form=recoverUserForm )

@superAdminBP.route("/admin-rbac", methods=["GET","POST"])
def roleManagement(): 
    role = sql_operation(table="role", mode="retrieve_all")
    roleList = []
    for role in role:
        roleList.append(RoleInfo(role))

    count = len(roleList)
    form = UpdateRoles(request.form)
    if (request.method == "POST"):
        roleName = form.roleName.data
        guestBP = request.form.get("guestBP1", default="off", type=str)
        generalBP = request.form.get("generalBP1", default="off", type=str)
        loggedInBP = request.form.get("loggedInBP1", default="off", type=str)
        teacherBP = request.form.get("teacherBP1", default="off", type=str)
        userBP = request.form.get("userBP1", default="off", type=str)

        guestBP = True if (guestBP.lower() == "on") else False
        generalBP = True if (generalBP.lower() == "on") else False
        loggedInBP = True if (loggedInBP.lower() == "on") else False
        teacherBP = True if (teacherBP.lower() == "on") else False
        userBP = True if (userBP.lower() == "on") else False

        sql_operation(
            table="role", mode="update_role", roleName=roleName, guestBP=guestBP, 
            generalBP=generalBP, loggedInBP=loggedInBP, teacherBP=teacherBP, 
            userBP=userBP
        )
        flash(f"The role, {roleName}, has been updated.", "Role Updated!")
        return redirect(url_for("superAdminBP.roleManagement"))

    return render_template("users/superadmin/admin_rbac.html", roleList=roleList, count=count,form=form)

@superAdminBP.route("/admin-create", methods=["GET","POST"])
def createAdmin():
    form = CreateAdmin(request.form)
    if (request.method == "POST" and form.validate()):
        username = form.username.data
        email = form.email.data
        sql_operation(table="user", mode="create_admin", username=username, email=email)
        flash(f"Admin created", "Role Updated!")
        return redirect(url_for("superAdminBP.adminManagement"))

    return render_template("users/superadmin/admin_create.html", form=form)