"""
Routes for logged in users (Students or Teachers or Admins)
"""
# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, \
                  Markup, abort, Blueprint, current_app, send_from_directory

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Forms import *

loggedInBP = Blueprint("loggedInBP", __name__, static_folder="static", template_folder="template")

@loggedInBP.route("/logout")
def logout():
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("guestBP.login"))

    sql_operation(table="session", mode="delete_session", sessionID=session["sid"])
    session.clear()
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("generalBP.home"))

# blocks all user from viewing the video so that they are only allowed to view the video from the purchase view
@loggedInBP.route("/static/course_videos/<string:courseID>/<string:videoName>")
def rawVideo(courseID:str, videoName:str):
    # TODO: Work on the video access control
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        if (userInfo.role == "Teacher" and sql_operation(table="course", mode="check_if_course_owned_by_teacher", teacherID=session["user"], courseID=courseID)):
            pass # allow access to the video for the teacher user if they own the course
        elif (userInfo.role == "Teacher" and "course-data" in session and session["course-data"][0] == courseID):
            pass # allow access to the video if the teacher user is in the midst of creating the course
        else:
            abort(404)

    # Allow the teacher to see the video if the teacher is in the midst of creating the course
    if ("course-data" in session):
        filePathArr = session["course-data"][1].rsplit("/", 2)[-2:]
        return send_from_directory(
            str(current_app.config["COURSE_VIDEO_FOLDER"].joinpath(filePathArr[0])), 
            filePathArr[1], 
            as_attachment=False, 
            max_age=31536000 # TODO: Check and configure the max age cache
        )

    videoPath = get_course_video_path(courseID, videoName)
    print("Formatted path:", videoPath)
    if (videoPath is None):
        abort(404)

    if (not convert_to_mpd(current_app.root_path + videoPath)):
        abort(500)

    # TODO: work on partial content request instead of sending the whole video file
    # TODO: Fix video player as it isn't loading/playing anymore
    return render_template("users/admin/raw_video.html", videoPath=videoPath)

@loggedInBP.route("/change-username", methods=["GET","POST"])
def updateUsername():
    if ("user" in session or "admin" in session):
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
    else:
        return redirect(url_for("guestBP.login"))

@loggedInBP.route("/change-password", methods=["GET","POST"])
def updatePassword():
    if ("user" in session or "admin" in session):
        userID = session.get("user") or session.get("admin")
        userInfo = get_image_path(userID, returnUserInfo=True)

        # check if user logged in via Google OAuth2 (Only for user and not admins)
        if (userInfo.googleOAuth):
            # if so, redirect to user profile as they cannot change their password
            return redirect(url_for("userBP.userProfile"))

        create_update_password_form = CreateChangePasswordForm(request.form)
        if (request.method == "POST" and create_update_password_form.validate()):
            currentPassword = create_update_password_form.currentPassword.data
            updatedPassword = create_update_password_form.password.data
            confirmPassword = create_update_password_form.cfmPassword.data

            if (updatedPassword != confirmPassword):
                flash("Passwords Do Not Match!")
                return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
            else:
                changed = False
                try:
                    sql_operation(table="user", mode="change_password", userID=userID, password=updatedPassword, oldPassword=currentPassword)
                    changed = True
                except (ChangePwdError):
                    flash("Please check your entries and try again.")
                except (PwdTooShortError, PwdTooLongError):
                    flash(f"Password must be between {current_app.config['CONSTANTS'].MIN_PASSWORD_LENGTH} and {current_app.config['CONSTANTS'].MAX_PASSWORD_LENGTH} characters long.")
                except (PwdTooWeakError):
                    flash("Password is too weak, please enter a stronger password!")
                except (haveibeenpwnedAPIDownError):
                    flash(Markup("Sorry! <a href='https://haveibeenpwned.com/API/v3' target='_blank' rel='noreferrer noopener'>haveibeenpwned's API</a> is down, please match all the password requirements for the time being!"))

                if (changed):
                    flash("Your password has been successfully changed.", "Account Details Updated!")
                    return redirect(url_for("userBP.userProfile")) if ("user" in session) else redirect(url_for("adminBP.adminProfile"))
                else:
                    return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
        else:
            return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
    else:
        return redirect(url_for("guestBP.login"))