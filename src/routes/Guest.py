"""
Routes for users who are not logged in (Guests)
"""
# import third party libraries
import requests as req, pyotp
from argon2.exceptions import HashingError

# for Google OAuth 2.0 login (Third-party libraries)
from cachecontrol import CacheControl
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google.auth.exceptions import GoogleAuthError

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, current_app

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Forms import *
from python_files.classes.Errors import *
from .RoutesSecurity import limiter
from .RoutesUtils import get_user_ip

# import python standard libraries
from zoneinfo import ZoneInfo
from datetime import datetime
from time import sleep
import random, html

guestBP = Blueprint("guestBP", __name__, static_folder="static", template_folder="template")
limiter.limit(limit_value=current_app.config["CONSTANTS"].DEFAULT_REQUEST_LIMIT)(guestBP)

@guestBP.route("/recover-account/<string:token>", methods=["GET","POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def recoverAccount(token:str):
    # verify the token and retrieve the userID if it is valid
    userID = sql_operation(table="expirable_token", mode="verify_recover_acc_token", token=token)
    if (userID is None):
        # if the token is invalid
        flash("Recovery account link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    resetPasswordForm = CreateResetPasswordForm(request.form)
    if (request.method == "POST" and resetPasswordForm.validate()):
        # check if password input and confirm password are the same
        passwordInput = resetPasswordForm.password.data

        pwnedPassword = pwd_has_been_pwned(passwordInput)
        if (isinstance(pwnedPassword, tuple) and not pwnedPassword[0]):
            # If the haveibeenpwned's API is down, tell user to match all requirements
            flash(Markup("Sorry! <a href='https://haveibeenpwned.com/API/v3' target='_blank' rel='noreferrer noopener'>haveibeenpwned's API</a> is down, please match all the password requirements for the time being!"))
            return render_template("users/guest/reset_password.html", form=resetPasswordForm)

        if (pwnedPassword):
            flash("Your password has been compromised, please use a different password!", "Danger")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm)
        if (not pwd_is_strong(passwordInput)):
            flash("Your password is not strong enough!", "Danger")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm)

        # update the password, remove the token from the database, and reactivate the user's account
        try:
            sql_operation(table="user", mode="reset_password", userID=userID, newPassword=passwordInput, token=token)
        except (HashingError) as e:
            write_log_entry(
                logMessage={
                    "User ID": userID,
                    "Purpose": "Reset Password",
                    "Argon2 Error": str(e)
                },
                severity="ERROR"
            )
            flash("An error occurred while resetting your password! Please try again later.", "Danger")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm)

        sql_operation(table="user", mode="reactivate_user", userID=userID)
        flash("Password has been reset successfully!", "Success")
        return redirect(url_for("guestBP.login"))
    else:
        return render_template("users/guest/reset_password.html", form=resetPasswordForm)

@guestBP.route("/login/disable-2fa", methods=["GET","POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def recoverAccountMFA():
    recoverForm = RecoverAccountMFAForm(request.form)
    if (request.method == "POST" and recoverForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Please verify that you are not a bot.")
            return render_template("users/guest/recover_account.html", form=recoverForm)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="recover_account")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Please verify that you are not a bot.")
            return render_template("users/guest/recover_account.html", form=recoverForm)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/recover_account.html", form=recoverForm)

        emailInput = recoverForm.email.data
        backupCodeInput = recoverForm.backupCode.data

        userID = sql_operation(table="user", mode="fetch_user_id_from_email", email=emailInput)
        if (userID is None):
            flash("Backup code is invalid!", "Danger")
            return render_template("users/guest/recover_account.html", form=recoverForm)

        if (not sql_operation(table="2fa_token", mode="disable_2fa_with_backup_code", backupCode=backupCodeInput, userID=userID)):
            flash("Backup code is invalid!", "Danger")
            return render_template("users/guest/recover_account.html", form=recoverForm)

        flash("2FA has been disabled successfully!", "Success")
        return redirect(url_for("guestBP.login"))
    else:
        return render_template("users/guest/recover_account.html", form=recoverForm)

@guestBP.route("/reset-password", methods=["GET", "POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def resetPasswordRequest():
    requestForm = RequestResetPasswordForm(request.form)
    if (request.method == "POST" and requestForm.validate()):
        # if the request is a post request and the form is valid
        # get the userID from the email
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/request_password_reset.html", form=requestForm)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="reset_password")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/request_password_reset.html", form=requestForm)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/request_password_reset.html", form=requestForm)

        emailInput = requestForm.email.data
        userInfo = sql_operation(table="user", mode="find_user_for_reset_password", email=emailInput)
        if (userInfo is None):
            # if the user does not exist
            sleep(random.uniform(2, 4)) # Artificial delay to prevent attacks such as enumeration attacks, etc.
            flash("Reset password instructions has been sent to your email if it's in our database!", "Success")
            return redirect(url_for("guestBP.login"))

        if (userInfo[1] is None):
            # if user has signed up using Google OAuth2
            # but is requesting for a password reset
            htmlBody = (
                "You are receiving this email due to a request to reset your password on your CourseFinity account.<br>If you did not make this request, please ignore this email.",
                f"Otherwise, please note that you had signed up to CourseFinity using your Google account.<br>Hence, please <a href='{current_app.config['CONSTANTS'].CUSTOM_DOMAIN}{url_for('guestBP.login')}' target='_blank'>login to CourseFinity</a> using your Google account.",
            )
            # send email to the user to remind them to login using Google account
            send_email(to=emailInput, subject="Reset Password", body="<br><br>".join(htmlBody))
            flash("Reset password instructions has been sent to your email if it's in our database!", "Success")
            return redirect(url_for("guestBP.login"))

        # create a token using the secrets library that is to be stored in the database 
        # with an active duration of 30 mins before it expires
        # and send the encrypted form of the token to user's email.
        # Note: The token in the database is not encrypted.
        encryptedToken = sql_operation(
            table="expirable_token", mode="add_token", 
            userID=userInfo[0], purpose="reset_password",
            expiryDate=ExpiryProperties(activeDuration=1800),
        )

        # send the token to the user's email
        htmlBody = (
            "You are receiving this email due to a request to reset your password on your CourseFinity account.<br>If you did not make this request, please ignore this email.",
            f"You can change the password on your account by clicking the button below.<br><a href='{current_app.config['CONSTANTS'].CUSTOM_DOMAIN}{url_for('guestBP.resetPassword', token=encryptedToken)}' style='{current_app.config['CONSTANTS'].EMAIL_BUTTON_STYLE}' target='_blank'>Click here to reset your password</a>"
        )
        send_email(to=emailInput, subject="Reset Password", body="<br><br>".join(htmlBody))

        flash("Reset password instructions has been sent to your email if it's in our database!", "Success")
        return redirect(url_for("guestBP.login"))
    else:
        return render_template("users/guest/request_password_reset.html", form=requestForm)

@guestBP.route("/reset-password/<string:token>", methods=["GET", "POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def resetPassword(token:str):
    # verify the token and retrieve the userID if it is valid
    userData = sql_operation(table="expirable_token", mode="verify_reset_pass_token", token=token)

    if (userData is None):
        # if the token is invalid
        flash("Reset password link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    userID, status, twoFAToken = userData[0], userData[1], userData[2]
    twoFAEnabled = True if (twoFAToken is not None) else False
    if (status != "Active"):
        # If the user is no longer active, then the token is invalid
        flash("Reset password link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    resetPasswordForm = CreateResetPasswordForm(request.form)
    if (request.method == "POST" and resetPasswordForm.validate()):
        # check if password input and confirm password are the same
        passwordInput = resetPasswordForm.password.data

        if (twoFAEnabled):
            # if 2FA is enabled, check if the 2FA token is valid
            twoFAInput = request.form.get("totpInput", default="", type=str)
            if (re.fullmatch(current_app.config["CONSTANTS"].TWO_FA_CODE_REGEX, twoFAInput) is None or not pyotp.TOTP(twoFAToken).verify(twoFAInput)):
                # if the 2FA token is invalid
                flash("Entered 2FA OTP is invalid or has expired!")
                return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

        pwnedPassword = pwd_has_been_pwned(passwordInput)
        if (isinstance(pwnedPassword, tuple) and not pwnedPassword[0]):
            # If the haveibeenpwned's API is down, tell user to match all requirements
            flash(Markup("Sorry! <a href='https://haveibeenpwned.com/API/v3' target='_blank' rel='noreferrer noopener'>haveibeenpwned's API</a> is down, please match all the password requirements for the time being!"))
            return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

        if (pwnedPassword):
            flash("Your password has been compromised, please use a different password!", "Danger")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)
        if (not pwd_is_strong(passwordInput)):
            flash("Your password is not strong enough!", "Danger")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

        # update the password and delete the token from the database after usage
        sql_operation(table="user", mode="reset_password", userID=userID, newPassword=passwordInput, token=token)
        flash("Password has been reset successfully!", "Success")
        return redirect(url_for("guestBP.login"))
    else:
        return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

@guestBP.route("/login", methods=["GET", "POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def login():
    loginForm = CreateLoginForm(request.form)
    if (request.method == "GET"):
        return render_template("users/guest/login.html", form=loginForm)

    if (request.method == "POST" and loginForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/guest/login.html", form=loginForm)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="login")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/guest/login.html", form=loginForm)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/guest/login.html", form=loginForm)

        requestIPAddress = get_user_ip()
        emailInput = loginForm.email.data
        passwordInput = loginForm.password.data
        userInfo = successfulLogin = isTeacher = userHasTwoFA = False
        try:
            # returns the userID, boolean if user logged in from a new IP address, username, role
            userInfo = sql_operation(table="user", mode="login", email=emailInput, password=passwordInput, ipAddress=requestIPAddress)

            # raise LoginFromNewIpAddressError("test") # for testing the guard authentication process
            isTeacher = True if (userInfo[3] == "Teacher") else False

            userHasTwoFA = sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userInfo[0])
            if (userInfo[1] and not userHasTwoFA):
                # login from new ip address and user did not enable 2FA
                raise LoginFromNewIpAddressError("Login from a new IP address!")

            successfulLogin = True
            sql_operation(table="login_attempts", mode="reset_user_attempts_for_user", userID=userInfo[0])
        except (UserIsNotActiveError, EmailDoesNotExistError):
            flash("Please check your entries or check if you have verified your email and try again!", "Danger")
        except (IncorrectPwdError):
            try:
                sql_operation(table="login_attempts", mode="add_attempt", email=emailInput)
                flash("Please check your entries or check if you have verified your email and try again!", "Danger")
            except (AccountLockedError):
                flash("Too many failed login attempts, please try again later.", "Danger")
        except (AccountLockedError):
            flash("Too many failed login attempts, please try again later.", "Danger")
        except (UserIsUsingOauth2Error, EmailNotVerifiedError):
            flash("Please check your entries or check if you have verified your email and try again!", "Danger")
        except (LoginFromNewIpAddressError):
            # sends an email with a generated 12 bytes token which is valid for 6 mins 
            # to authenticate the user if login was successful.
            generatedSecretToken = sql_operation(table="guard_token", mode="add_token", userID=userInfo[0])

            try:
                ipDetails = current_app.config["SECRET_CONSTANTS"].IPINFO_HANDLER.getDetails(requestIPAddress).all
            except (req.exceptions.ConnectionError, req.exceptions.ReadTimeout) as e:
                write_log_entry(
                    logMessage=f"Error while getting IP details from ipinfo.io: {e}",
                    severity="INFO"
                )
                ipDetails = {}

            # utc+8 time (SGT)
            currentDatetime = datetime.now().astimezone(tz=ZoneInfo("Asia/Singapore"))
            currentDatetime = currentDatetime.strftime("%d %B %Y, %H:%M:%S %z")

            # format the string location from the ip address details
            locationString = ""
            if (ipDetails.get("city") is not None):
                locationString += ipDetails["city"]
            else:
                locationString += "Unknown city"

            if (ipDetails.get("region") is not None):
                if (locationString != ""):
                    locationString += ", "
                locationString += ipDetails["region"]
            else:
                locationString += ", Unknown region"

            if (ipDetails.get("country_name") is not None):
                if (locationString != ""):
                    locationString += ", "
                locationString += ipDetails["country_name"]
            else:
                locationString += ", Unknown country"

            messagePartList = (
                f"Your CourseFinity account, {emailInput}, was logged in to from a new IP address.", 
                f"Time: {currentDatetime} (SGT)<br>Location*: {locationString}<br>New IP Address: {requestIPAddress}",
                "* Location is approximate based on the login's IP address.",
                f"Please enter the generated code below to authenticate yourself.<br>Generated Code (will expire in 8 minutes!):<br><strong>{generatedSecretToken}</strong>", 
                f"If this was not you, we recommend that you <strong>change your password immediately</strong> by clicking the link below.<br>Change password:<br>{current_app.config['CONSTANTS'].CUSTOM_DOMAIN}{url_for('userBP.updatePassword')}"
            )
            send_email(to=emailInput, subject="Unfamiliar Login Attempt", body="<br><br>".join(messagePartList))
            session["ip_details"] = ipDetails

            # Check if password has been compromised using haveibeenpwned's API,
            # If the API is down, then we will not check for the time being
            passwordCompromised = pwd_has_been_pwned(passwordInput)
            if (isinstance(passwordCompromised, tuple)):
                session["password_compromised"] = False
            else:
                session["password_compromised"] = passwordCompromised

            session["temp_uid"] = userInfo[0]
            flash("An email has been sent to you with your special access code!", "Success")
            return redirect(url_for("guestBP.enterGuardTOTP"))

        passwordCompromised = None
        if (successfulLogin):
            # Check if password has been compromised using haveibeenpwned's API,
            # If the API is down, then we will not check for the time being
            # Otherwise, if the API is available, check if compromised.
            # If so, we will send an email to the user and flash a message
            # on the home page after the login process
            passwordCompromised = pwd_has_been_pwned(passwordInput)
            if (isinstance(passwordCompromised, tuple)):
                passwordCompromised = False

        if (successfulLogin and not userHasTwoFA):
            session["sid"] = add_session(userInfo[0], userIP=get_user_ip(), userAgent=request.user_agent.string)
            session["user"] = userInfo[0]
            session["isTeacher"] = isTeacher

            if (passwordCompromised):
                send_change_password_alert_email(email=emailInput)
                return redirect(url_for("generalBP.home"))
            return redirect(url_for("generalBP.home"))
        elif (successfulLogin and userHasTwoFA):
            # if user has 2fa enabled and is 
            # logged in from a known ip address
            session["password_compromised"] = passwordCompromised
            session["temp_uid"] = userInfo[0]
            return redirect(url_for("guestBP.enter2faTOTP"))
        else:
            write_log_entry(
                logMessage=f"Failed login attempt for user: \"{emailInput}\", with the following IP address: {get_user_ip()}", 
                severity="NOTICE"
            )
            sleep(random.uniform(2, 4)) # Artificial delay to prevent attacks such as enumeration attacks, etc.
            return render_template("users/guest/login.html", form=loginForm)
    else:
        return render_template("users/guest/login.html", form = loginForm)

@guestBP.route("/unlock-account/<string:token>")
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def unlockAccount(token:str):
    # verify the token and reset the login attempts if validated
    resetFlag = sql_operation(table="expirable_token", mode="verify_unlock_acc_token", token=token)
    if (not resetFlag):
        # if the token is invalid
        flash("Unlock account link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    flash("Your account has been unlocked! Try logging in now!", "Success")
    return redirect(url_for("guestBP.login"))

@guestBP.route("/verify-login", methods=["GET", "POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def enterGuardTOTP():
    """
    This page is only accessible to users who are logging but from a new IP address.
    """
    if (
        "ip_details" not in session or
        "password_compromised" not in session or 
        "temp_uid" not in session
    ):
        session.clear()
        return redirect(url_for("guestBP.login"))

    if (session["ip_details"]["ip"] != get_user_ip()):
        flash("IP address does not match login request, please try again!", "Danger")
        session.clear()
        return redirect(url_for("guestBP.login"))

    guardAuthForm = guardTokenForm(request.form)
    if (request.method == "GET"):
        return render_template("users/guest/guard_token.html", form=guardAuthForm)

    if (request.method == "POST" and guardAuthForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/guest/guard_token.html", form=guardAuthForm)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="enter_guard_token")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/guest/guard_token.html", form=guardAuthForm)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/guest/guard_token.html", form=guardAuthForm)

        userID = session["temp_uid"]
        tokenInput = guardAuthForm.guardToken.data
        if (not sql_operation(
            table="guard_token", mode="verify_token", token=tokenInput, ipAddress=get_user_ip(), userID=userID)
        ):
            write_log_entry(
                logMessage=f"Failed guard 2FA login verification attempt for user: \"{session['temp_uid']}\", with the following IP address: {get_user_ip()}", 
                severity="NOTICE"
            )
            flash("Please check your entries and try again!", "Danger")
            return render_template("users/guest/guard_token.html", form=guardAuthForm)

        passwordCompromised = session["password_compromised"]
        session.clear()

        session["sid"] = add_session(userID, userIP=get_user_ip(), userAgent=request.user_agent.string)
        userInfo = get_image_path(userID, returnUserInfo=True)

        # check if password has been compromised
        # if so, flash a message and send an email to the user
        if (passwordCompromised):
            send_change_password_alert_email(email=userInfo.email)

        session["user"] = userID
        return redirect(url_for("generalBP.home"))

    # post request with invalid form values
    return render_template("users/guest/guard_token.html", form=guardAuthForm)

@guestBP.route("/login-google")
def loginViaGoogle():
    # https://developers.google.com/identity/protocols/oauth2/web-server#python
    authorisationUrl, state = get_google_flow().authorization_url(
        # Enable offline access so that you can refresh an
        # access token without re-prompting the user for permission
        access_type="offline",

        # Enable incremental authorization
        # Recommended as a best practice according to Google documentation
        include_granted_scopes="true"
    )

    # Store the state so the callback can verify the auth server response
    session["state"] = symmetric_encrypt(
        plaintext=state, keyID=current_app.config["CONSTANTS"].COOKIE_ENCRYPTION_KEY_ID
    )
    return redirect(authorisationUrl)

@guestBP.route("/login-callback")
def loginCallback():
    if ("state" not in session):
        return redirect(url_for("guestBP.login"))

    googleOauthFlow = get_google_flow()
    try:
        googleOauthFlow.fetch_token(authorization_response=request.url)
    except (Exception) as e:
        write_log_entry(
            logMessage={
                "Google OAuth2 login error": str(e),
                "Google OAuth2 request url": request.url,
                "User's IP address": get_user_ip()
            },
            severity="NOTICE"
        )
        flash("An error occurred while trying to login via Google!", "Danger")
        return redirect(url_for("guestBP.login"))

    decryptedState = symmetric_decrypt(
        ciphertext=session["state"], keyID=current_app.config["CONSTANTS"].COOKIE_ENCRYPTION_KEY_ID
    )
    if (decryptedState != request.args.get("state", default="", type=str)):
        abort(500) # when state does not match (protect against CSRF attacks)

    credentials = googleOauthFlow.credentials
    requestSession = req.session()
    cachedSession = CacheControl(requestSession)
    tokenRequest = GoogleRequest(session=cachedSession)

    try:
        # clock_skew_in_seconds=10 seconds as it might take some time to retreive the token from Google API
        idInfo = id_token.verify_oauth2_token(
            credentials.id_token,
            tokenRequest, 
            audience=current_app.config["SECRET_CONSTANTS"].GOOGLE_CREDENTIALS["web"]["client_id"],
            clock_skew_in_seconds=10
        )
    except (ValueError, GoogleAuthError, KeyError):
        flash("Failed to verify Google login! Please try again!", "Danger")
        return redirect(url_for("guestBP.login"))

    # check if the Google account has its email address verified
    emailVerificationStatus = idInfo["email_verified"]
    if (not emailVerificationStatus):
        session.clear()
        flash("Sorry, please verify your Google email address before logging in!", "Danger")
        return redirect(url_for("guestBP.login"))

    userID = idInfo["sub"]
    email = idInfo["email"]
    username = idInfo["name"]
    profilePicture = idInfo["picture"]

    # add to db if user does not exist and retrieve the role of the user
    returnedValue = sql_operation(table="user", mode="login_google_oauth2", userID=userID, username=username, email=email, googleProfilePic=profilePicture)
    if (returnedValue is None):
        # if user does not exist yet
        returnedID = None
        returnedRole = "Student"
    else:
        # if user exist, use the returned value for the userID and role of the user
        returnedID = returnedValue[0]
        returnedRole = returnedValue[1]

    # if returnedID is not None, ignore the userID from Google
    # This happens if the user signed up through CourseFinity but used Google OAuth2 to sign in
    userID = returnedID or userID
    session.clear()

    # assign the session accordingly based on the role of the user
    if (returnedRole == "Admin" or returnedRole == "SuperAdmin"):
        session["admin"] = userID
        if (returnedRole == "SuperAdmin"):
            session["isSuperAdmin"] = True 
    else:
        session["user"] = userID
        session["isTeacher"] = True if (returnedRole == "Teacher") else False

    session["sid"] = add_session(userID, userIP=get_user_ip(), userAgent=request.user_agent.string)
    return redirect(url_for("generalBP.home"))

@guestBP.route("/signup", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def signup():
    signupForm = CreateSignUpForm(request.form)
    if (request.method == "GET"):
        return render_template("users/guest/signup.html", form=signupForm)

    if (request.method == "POST" and signupForm.validate()):
        # POST request code below
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Please verify that you are not a bot.")
            return render_template("users/guest/signup.html", form=signupForm)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="signup")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/signup.html", form=signupForm)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/signup.html", form=signupForm)

        emailInput = signupForm.email.data
        usernameInput = signupForm.username.data
        passwordInput = signupForm.password.data

        pwnedPassword = pwd_has_been_pwned(passwordInput)
        if (isinstance(pwnedPassword, tuple) and not pwnedPassword[0]):
            # If the haveibeenpwned's API is down, tell user to match all requirements
            flash(Markup("Sorry! <a href='https://haveibeenpwned.com/API/v3' target='_blank' rel='noreferrer noopener'>haveibeenpwned's API</a> is down, please match all the password requirements for the time being!"))
            return render_template("users/guest/signup.html", form=signupForm)

        if (pwnedPassword):
            flash("Your password has been compromised, please use a different password!", "Danger")
            return render_template("users/guest/signup.html", form=signupForm)
        if (not pwd_is_strong(passwordInput)):
            flash("Your password is too weak, please enter a stronger password!")
            return render_template("users/guest/signup.html", form=signupForm)

        try:
            passwordInput = current_app.config["CONSTANTS"].PH.hash(passwordInput)
        except (HashingError) as e:
            write_log_entry(
                logMessage={
                    "Purpose": "Signup",
                    "Argon2 Error": str(e)
                }
            )
            flash("Sorry! Something went wrong, please try again!")
            return render_template("users/guest/signup.html", form=signupForm)

        ipAddress = get_user_ip()
        returnedVal = sql_operation(table="user", mode="signup", email=emailInput, username=usernameInput, password=passwordInput, ipAddress=ipAddress)

        if (isinstance(returnedVal, tuple)):
            usernameDupe = returnedVal[1]
            # Flash messages with reference to:
            # https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-creation
            if (usernameDupe):
                flash("Username already exists!") # It's okay to show this since the login page uses the email
                return render_template("users/guest/signup.html", form=signupForm)
            else: # if emailDupe
                flash("A link to verify your email has been emailed to the address provided!", "Success")
                return redirect(url_for("guestBP.login"))

        try:
            send_verification_email(email=emailInput, username=usernameInput, userID=returnedVal)
            flash("A link to verify your email has been emailed to the address provided!", "Success")
        except (Exception) as e:
            #TODO: Fix it anyways but can't be XSSed i believed
            write_log_entry(
                logMessage=f"Error sending verification email: {e}",
                severity="ERROR",
            )
            flash(
                Markup(f"Failed to send email! Please try again by clicking <a href='{url_for('guestBP.sendVerifyEmail')}?user={html.escape(returnedVal)}'>me</a>!"),
                "Danger"
            )
            return redirect(url_for("guestBP.login"))
        return redirect(url_for("guestBP.login"))
    else:
        # post request but form inputs are not valid
        return render_template("users/guest/signup.html", form=signupForm)

@guestBP.route("/send-verify-email")
@limiter.limit("30 per minute")
def sendVerifyEmail():
    userID = request.args.get("user", default=None, type=str)
    if (userID is None):
        abort(404)

    userInfo = sql_operation(table="user", mode="get_user_data", userID=userID)
    if (userInfo and not userInfo.emailVerified):
        email = userInfo.email
        username = userInfo.username
        try:
            send_verification_email(email=email, username=username, userID=userID)
            flash(f"An email has bent sent to you to verify your email!", "Success")
        except (Exception) as e:
            write_log_entry(
                logMessage=f"Error sending verification email: {e}",
                severity="ERROR",
            )
            flash(
                Markup(f"Failed to send email! Please try again by clicking <a href='{url_for('guestBP.sendVerifyEmail')}?user={html.escape(userID)}'>me</a> later!"),
                "Danger"
            )
        return redirect(url_for("guestBP.login"))
    else:
        # If user does not exist or already has its email verified
        abort(404)

@guestBP.route("/enter-2fa", methods=["GET", "POST"])
@limiter.limit(current_app.config["CONSTANTS"].SENSITIVE_PAGE_LIMIT)
def enter2faTOTP():
    """
    This page is only accessible to users who have 2FA enabled and is trying to login.
    """
    if (
        "password_compromised" not in session or
        "temp_uid" not in session
    ):
        session.clear()
        return redirect(url_for("guestBP.login"))

    twoFactorAuthForm = twoFAForm(request.form)
    if (request.method == "GET"):
        return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm)

    if (request.method == "POST" and twoFactorAuthForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="enter_two_fA")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!")
            return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm)

        twoFAInput = twoFactorAuthForm.twoFATOTP.data
        userID = session["temp_uid"]
        try:
            getSecretToken = sql_operation(table="2fa_token", mode="get_token", userID=userID)
        except (No2FATokenError):
            # if for whatever reasons, the user has no 2FA token (which shouldn't happen), redirect to login
            return redirect(url_for("guestBP.login"))

        if (pyotp.TOTP(getSecretToken).verify(twoFAInput)):
            session["user"] = userID
            session["sid"] = add_session(userID, userIP=get_user_ip(), userAgent=request.user_agent.string)
            userInfo = get_image_path(userID, returnUserInfo=True)

            # check if password has been compromised
            # if so, flash a message and send an email to the user
            if (session["password_compromised"]):
                send_change_password_alert_email(email=userInfo.email)

            session["isTeacher"] = True if (userInfo.role == "Teacher") else False
            return redirect(url_for("generalBP.home"))
        else:
            flash("Invalid 2FA code, please try again!")
            return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm)

    # post request but form inputs are not valid
    return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm)