"""
Routes for logged in users (Students or Teachers or Admins)
"""
# import third party libraries
import pyotp, qrcode

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, Markup, abort, Blueprint, current_app
from flask_limiter.util import get_remote_address

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Forms import *

# import python standard libraries
from base64 import b64encode
from io import BytesIO

loggedInBP = Blueprint("loggedInBP", __name__, static_folder="static", template_folder="template")

@loggedInBP.route("/logout")
def logout():
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("guestBP.login"))

    sql_operation(table="session", mode="delete_session", sessionID=session["sid"])
    session.clear()
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("generalBP.home"))

@loggedInBP.route("/setup-2fa", methods=["GET", "POST"])
def twoFactorAuthSetup():
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("guestBP.login"))

    if ("user" in session):
        userID = session["user"]
    elif ("admin" in session):
        userID = session["admin"]
    userInfo = get_image_path(userID, returnUserInfo=True)

    # check if user logged in via Google OAuth2
    if (userInfo.googleAuth == True):
        # if so, redirect to user profile as the authentication security is handled by Google themselves
        flash(Markup("You had signed up with Google OAuth2 on CourseFinity.<br>Please <a href='https://support.google.com/accounts/answer/185839?hl=en' target='_blank' rel='noopener noreferrer'>setup 2FA for your Google account</a> instead!"))
        return redirect(url_for("userBP.userProfile"))

    # check if user has already setup 2fa
    if (userInfo.hasTwoFA):
        return redirect(url_for("userBP.userProfile"))

    twoFactorAuthForm = twoFAForm(request.form)
    if (request.method == "GET"):
        # for google authenticator setup key (20 byte)
        if ("2fa_token" not in session):
            secretToken = pyotp.random_base32() # MUST be kept secret
            session["2fa_token"] = RSA_encrypt(plaintext=secretToken)
        else:
            secretToken = RSA_decrypt(plaintext=session["2fa_token"])

        # generate a QR code for the user to scan
        totp = pyotp.totp.TOTP(s=secretToken, digits=6).provisioning_uri(name=userInfo.username, issuer_name="CourseFinity")

        # to save the image in the memory buffer
        # instead of saving the qrcode png as a file in the web server
        stream = BytesIO()

        # create a qrcode object
        qrCodeData = qrcode.make(totp, box_size=15)

        # save the qrcode image in the memory buffer
        qrCodeData.save(stream)

        # get the image from the memory buffer and encode it into base64
        qrCodeEncodedBase64 = b64encode(stream.getvalue()).decode()

        return render_template("users/loggedin/2fa.html", form=twoFactorAuthForm, imageSrcPath=userInfo.profileImage, qrCodeEncodedBase64=qrCodeEncodedBase64, secretToken=secretToken, accType=userInfo.role)

    if (request.method == "POST" and twoFactorAuthForm.validate()):
        # POST request code below
        if ("2fa_token" not in session):
            return redirect(url_for("loggedInBP.twoFactorAuthSetup"))

        twoFATOTP = twoFactorAuthForm.twoFATOTP.data
        secretToken = request.form.get("secretToken")
        if (secretToken is None or secretToken != RSA_decrypt(cipherData=session["2fa_token"])):
            flash("Please check your entry and try again!")
            return redirect(url_for("loggedInBP.twoFactorAuthSetup"))

        # if the secret token and the session token is equal but
        # the secret token is not base32, then the user has tampered with the session
        # and the html 2FA secretToken hidden form value
        if (not two_fa_token_is_valid(secretToken)):
            session.pop("2fa_token", None)
            flash("Invalid 2FA setup key, please try again!", "Danger")
            write_log_entry(
                logLocation="coursefinity-web-app",
                logMessage=f"User: {userID}, IP address: {get_remote_address()}, 2FA token matches session token but is not base32.",
                severity="ALERT"
            )
            return redirect(url_for("loggedInBP.twoFactorAuthSetup"))

        # check if the TOTP is valid
        if (pyotp.TOTP(secretToken).verify(twoFATOTP)):
            # update the user's 2FA status to True
            sql_operation(table="2fa_token", mode="add_token", userID=userInfo.uid, token=secretToken)
            flash(Markup("2FA has been <span class='text-success'>enabled</span> successfully!<br>You will now be prompted to key in your time-based OTP whenever you login now!"), "2FA has been enabled!")
            return redirect(url_for("userBP.userProfile"))
        else:
            flash("Please check your entry and try again!")
            return redirect(url_for("loggedInBP.twoFactorAuthSetup"))

    # post request but form inputs are not valid
    return redirect(url_for("loggedInBP.twoFactorAuthSetup"))

@loggedInBP.post("/disable-2fa")
def disableTwoFactorAuth():
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("guestBP.login"))

    if ("user" in session):
        userID = session["user"]
    elif ("admin" in session):
        userID = session["admin"]

    # check if user logged in via Google OAuth2
    try:
        loginViaGoogle = sql_operation(table="user", mode="check_if_using_google_oauth2", userID=userID)
    except (UserDoesNotExist):
        abort(403) # if for whatever reason, a user does not exist, abort

    if (loginViaGoogle):
        # if so, redirect to user profile as the authentication security is handled by Google themselves
        return redirect(url_for("userBP.userProfile"))

    if (sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userID)):
        sql_operation(table="2fa_token", mode="delete_token", userID=userID)
        flash(Markup("Two factor authentication has been <span class='text-danger'>disabled</span>!<br>You will no longer be prompted to enter your 2FA time-based OTP."), "2FA Disabled!")
    else:
        flash("You do not have 2FA enabled!", "2FA Is NOT Enabled!")

    return redirect(url_for("userBP.userProfile")) if ("user" in session) else redirect(url_for("adminBP.adminProfile"))

@loggedInBP.route("/change-username", methods=["GET","POST"])
def updateUsername():
    if ("user" in session or "admin" in session):
        userID = session.get("user") or session.get("admin")
        userInfo = get_image_path(userID, returnUserInfo=True)

        create_update_username_form = CreateChangeUsername(request.form)
        if (request.method == "POST") and (create_update_username_form.validate()):
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
        if (request.method == "POST") and (create_update_password_form.validate()):
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