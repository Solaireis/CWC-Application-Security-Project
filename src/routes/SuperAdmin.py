"""
Routes for admin users
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, redirect, url_for, session, request, current_app
from urllib.parse import quote_plus, unquote_plus

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Roles import RoleInfo
from python_files.classes.Forms import *


superAdminBP = Blueprint("superAdminBP", __name__, static_folder="static", template_folder="template")

@superAdminBP.route("/admin-management", methods=["GET","POST"])
def adminManagement():
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

        if (formType == "recoverUser" and not userInfo.googleOAuth):
            isRecovering = sql_operation(table="recovery_token", mode="check_if_recovering", userID=userID)
            if (isRecovering):
                flash(
                    Markup("The user's account is already in the process of being recovered.<br>However, if you wish to revoke the recovery process, please do that instead of recovering the user's account again."), 
                    "Recovering User's Account Request Rejected"
                )
            elif (recoverUserForm.validate()):
                newEmail = recoverUserForm.email.data 
                try:
                    # deactivate user's account to prevent the attacker from changing the email address again
                    sql_operation(table="user", mode="deactivate_user", userID=userID)

                    # change user's email address to the new one
                    sql_operation(table="user", mode="admin_change_email", userID=userID, email=newEmail)
                    
                    flash(f"The user, {userID}, has its email changed to {newEmail} and the instructions to reset his/her password has bent sent to the new email.", f"User's Account Details Updated!")

                    token, tokenID = generate_limited_usage_jwt_token(payload={"userID": userID}, limit=1, getTokenIDFlag=True)
                    sql_operation(table="recovery_token", mode="add_token", userID=userID, tokenID=tokenID, oldUserEmail=userInfo.email)

                    htmlBody = [
                        "Great news! Your account has been recovered by an administrator on our side.<br>",
                        f"Your account email address has been changed to {newEmail} during the account recovery process.",
                        "However, you still need to reset your password by clicking the link below.<br>",
                        "Please click the link below to reset your password.",
                        f"<a href='{url_for('guestBP.recoverAccount', _external=True, token=token)}' style='{current_app.config['CONSTANTS'].EMAIL_BUTTON_STYLE}' target='_blank'>Reset Password</a>",
                        "Note: This link will ONLY expire upon usage."
                    ]
                    send_email(to=newEmail, subject="Account Recovery", body="<br>".join(htmlBody))
                except (SameAsOldEmailError):
                    flash("The new email entered is the same as the old email...", "Error recovering user's account!")
                except (EmailAlreadyInUseError):
                    flash("The new email entered is already in use...", "Error recovering user's account!")
            else:
                flash("The email provided was invalid when recovering the user's account.", "Error recovering user's account!")

        elif (formType == "revokeRecoveryProcess" and not userInfo.googleOAuth):
            isRecovering = sql_operation(table="recovery_token", mode="check_if_recovering", userID=userID)
            if (isRecovering):
                sql_operation(table="recovery_token", mode="revoke_token", userID=userID)
                flash(f"The user's account recovery process has been revoked and the account has been reactivated for the user.", "Recovery Process Revoked!")
            else:
                flash("The user's account is not in the process of being recovered.", "Error Revoking Recovery Process!")

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

    # Pagination starts below
    pageNum = request.args.get("p", default=1, type=int)
    userInput = request.args.get("user", default=None, type=str)
    userInput = quote_plus(userInput) if (userInput is not None) else None
    if (userInput is not None):
        filterInput = request.args.get("filter", default="username", type=str)
        if (filterInput not in ("username", "uid", "email")):
            filterInput = "username"

        userInput = userInput[:100] # limit user input to 100 characters to avoid buffer overflow when querying in MySQL
        userArr, maxPage = sql_operation(table="user", mode="paginate_admins", pageNum=pageNum, userInput=unquote_plus(userInput), filterType=filterInput)
    else:
        print(sql_operation(table="user", mode="paginate_admins", pageNum=pageNum))
        userArr, maxPage = sql_operation(table="user", mode="paginate_admins", pageNum=pageNum)

    if (pageNum > maxPage):
        if (userInput is not None):
            return redirect(f"{url_for('superAdminBP.adminManagement')}?user={userInput}&filter={filterInput}&p={maxPage}")
        else:
            return redirect(f"{url_for('superAdminBP.adminManagement')}?p={maxPage}")
    elif (pageNum < 1):
        if (userInput is not None):
            return redirect(f"{url_for('superAdminBP.adminManagement')}?user={userInput}&filter={filterInput}&p=1")
        else:
            return redirect(f"{url_for('superAdminBP.adminManagement')}?p=1")

    # Compute the buttons needed for pagination
    paginationArr = get_pagination_arr(pageNum=pageNum, maxPage=maxPage)

    # save the current URL in the session for when the admin searches and an error occurs
    session["relative_url"] = request.full_path
    return render_template("users/superadmin/admin_management.html", currentPage=pageNum, userArr=userArr, maxPage=maxPage, paginationArr=paginationArr, form=recoverUserForm)

@superAdminBP.route("/admin-rbac", methods=["GET","POST"])
def roleManagement(): #TODO Create Admin Accounts Create a form to edit the roles permission, first retrieve the information
    role = sql_operation(table="role", mode="retrieve_all")
    roleList = []
    for role in role:
        roleList.append(RoleInfo(role))

    count = len(roleList)
    for role in roleList:
        print(role.roleName)

    # Check if user is logged in
    # TODO: Role Management do not need pagination and relative url session
    return render_template("users/superadmin/admin_rbac.html", roleList=roleList, count=count)