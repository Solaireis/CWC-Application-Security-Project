"""
Routes for admin users
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, redirect, url_for, session, request, current_app
from urllib.parse import quote_plus, unquote_plus

from sqlalchemy import null

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Roles import RoleInfo
from python_files.classes.Forms import *


superAdminBP = Blueprint("superAdminBP", __name__, static_folder="static", template_folder="template")

@superAdminBP.route("/admin-management", methods=["GET","POST"])
def adminManagement():
    #get the role of the user
    
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
    return render_template("users/superadmin/admin_management.html", currentPage=pageNum, userArr=userArr, maxPage=maxPage, paginationArr=paginationArr, form=recoverUserForm )

@superAdminBP.route("/admin-rbac", methods=["GET","POST"])
def roleManagement(): #TODO Create Admin Accounts Create a form to edit the roles permission, first retrieve the information
    role = sql_operation(table="role", mode="retrieve_all")
    roleList = []
    for role in role:
        roleList.append(RoleInfo(role))

    count = len(roleList)
    for role in roleList:
        print(role.roleName)

    form = UpdateRoles(request.form)
    if (request.method == "POST" and form.validate()):
        # formType = request.form.get("formType", default=None, type=str)
        
        roleName = form.roleName.data
        guestBP = form.guestBP.data
        generalBP = form.generalBP.data
        adminBP = form.adminBP.data
        loggedInBP = form.loggedInBP.data
        errorBP = form.errorBP.data
        teacherBP = form.teacherBP.data
        userBP = form.userBP.data
        superAdminBP = form.superAdminBP.data

        guestBP1 = request.form.get("guestBP1")
        generalBP1 = request.form.get("generalBP1")
        adminBP1 = request.form.get("adminBP1")
        loggedInBP1 = request.form.get("loggedInBP1")
        errorBP1 = request.form.get("errorBP1")
        teacherBP1 = request.form.get("teacherBP1")
        userBP1 = request.form.get("userBP1")
        superAdminBP1 = request.form.get("superAdminBP1")
        print(guestBP1, generalBP1, adminBP1, loggedInBP1, errorBP1, teacherBP1, userBP1, superAdminBP1)
        
        #TODO create input validations for the form

        if (guestBP is null):
            guestBP = 0
        elif (guestBP.lower() == "on"):
            guestBP = 1
        else:
            guestBP = 0
        
        if (generalBP is null):
            generalBP = 0
        elif (generalBP.lower() == "on"):
            generalBP = 1
        else:
            generalBP = 0
            
        if (adminBP is null):
            adminBP = 0
        elif (adminBP.lower() == "on"):
            adminBP = 1
        else:
            adminBP = 0

        if (loggedInBP is null):
            loggedInBP = 0
        elif (loggedInBP.lower() == "on"):
            loggedInBP = 1
        else:
            loggedInBP = 0

        if (errorBP is null):
            errorBP = 0
        elif (errorBP.lower() == "on"):
            errorBP = 1
        else:
            errorBP = 0

        if (teacherBP is null):
            teacherBP = 0
        elif (teacherBP.lower() == "on"):
            teacherBP = 1
        else:
            teacherBP = 0

        if (userBP is null):
            userBP = 0
        elif (userBP.lower() == "on"):
            userBP = 1
        else:
            userBP = 0

        if (superAdminBP is null):
            superAdminBP = 0
        elif (superAdminBP.lower() == "on"):
            superAdminBP = 1
        else:
            superAdminBP = 0
            

        sql_operation(table="role", mode="update_role", roleName=roleName, guestBP=guestBP, generalBP=generalBP, adminBP=adminBP, loggedInBP=loggedInBP, errorBP=errorBP, teacherBP=teacherBP, userBP=userBP, superAdminBP=superAdminBP)
        flash(f"The role, {roleName}, has been updated.", "Role Updated!")
        return redirect(url_for("superAdminBP.roleManagement"))

    # TODO: Role Management do not need pagination and relative url session
    return render_template("users/superadmin/admin_rbac.html", roleList=roleList, count=count,form=form)

    

@superAdminBP.route("/admin-create", methods=["GET","POST"])
def createAdmin():
    form = CreateAdmin(request.form)
    if (request.method == "POST" and form.validate()):
        username = form.username.data
        email = form.email.data
        print("success")
        sql_operation(table="user", mode="create_admin", username=username, email=email)
        flash(f"Admin created", "Role Updated!")
        return redirect(url_for("superAdminBP.adminManagement"))

    return render_template("users/superadmin/admin_create.html", form=form)