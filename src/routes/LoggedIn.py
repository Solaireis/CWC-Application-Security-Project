"""
Routes for logged in users (Students or Teachers or Admins)
"""
# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, Blueprint

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Forms import *

loggedInBP = Blueprint("loggedInBP", __name__, static_folder="static", template_folder="template")

@loggedInBP.route("/logout")
def logout():
    sql_operation(table="session", mode="delete_session", sessionID=session["sid"])
    session.clear()
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("generalBP.home"))

@loggedInBP.route("/change-username", methods=["GET","POST"])
def updateUsername():
    userID = session.get("user") or session.get("admin")
    userInfo = get_image_path(userID, returnUserInfo=True)

    create_update_username_form = CreateChangeUsername(request.form)
    if (request.method == "POST" and create_update_username_form.validate()):
        updatedUsername = create_update_username_form.updateUsername.data

        changed = False
        try:
            sql_operation(table="user", mode="change_username", userID=userID, username=updatedUsername)
            changed = True
            flash("Your username has been successfully changed.", "Account Details Updated!")
        except (ReusedUsernameError):
            flash("Sorry, Username has already been taken!")

        if (changed):
            return redirect(url_for("userBP.userProfile")) if ("user" in session) else redirect(url_for("adminBP.adminProfile"))
        else:
            return render_template("users/loggedin/change_username.html", form=create_update_username_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
    else:
        return render_template("users/loggedin/change_username.html", form=create_update_username_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)