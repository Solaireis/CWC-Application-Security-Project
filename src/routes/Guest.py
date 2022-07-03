"""
Routes for users who are not logged in (Guests)
"""
# import third party libraries
import requests as req
import pyotp

# for Google OAuth 2.0 login (Third-party libraries)
from cachecontrol import CacheControl
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google.auth.exceptions import GoogleAuthError

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, current_app
from flask_limiter.util import get_remote_address

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.classes.Forms import *
from python_files.classes.Errors import *
from python_files.classes.Constants import CONSTANTS
from .RoutesLimiter import limiter

# import python standard libraries
from zoneinfo import ZoneInfo
from datetime import datetime

guestBP = Blueprint("guestBP", __name__, static_folder="static", template_folder="template")
limiter.limit(limit_value=CONSTANTS.REQUEST_LIMIT)(guestBP)

@guestBP.before_app_first_request
def before_first_request() -> None:
    """
    Called called at the very first request to the web app.

    Returns:
    - None
    """
    # load google client id from credentials.json
    current_app.config["GOOGLE_CLIENT_ID"] = CONSTANTS.GOOGLE_CREDENTIALS["web"]["client_id"]

    # get Google oauth flow object
    current_app.config["GOOGLE_OAUTH_FLOW"] = get_google_flow()

@guestBP.route("/reset-password", methods=["GET", "POST"])
def resetPasswordRequest():
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    requestForm = RequestResetPasswordForm(request.form)
    if (request.method == "POST" and requestForm.validate()):
        # if the request is a post request and the form is valid
        # get the userID from the email
        emailInput = requestForm.email.data
        userInfo = sql_operation(table="user", mode="find_user_for_reset_password", email=emailInput)
        if (userInfo is None):
            # if the user does not exist
            time.sleep(1) # wait one second to throw off attackers
            flash("Reset password instructions has been sent to your email!", "Success")
            return redirect(url_for("guestBP.login"))

        if (userInfo[1] is None):
            # if user has signed up using Google OAuth2
            # but is requesting for a password reset
            htmlBody = [
                "You are receiving this email due to a request to reset your password on your CourseFinity account.<br>If you did not make this request, please ignore this email.",
                f"Otherwise, please note that you had signed up to CourseFinity using your Google account.<br>Hence, please <a href='{url_for('guestBP.login', _external=True)}' target='_blank'>login to CourseFinity</a> using your Google account.",
            ]
            # send email to the user to remind them to login using Google account
            send_email(to=emailInput, subject="Reset Password", htmlBody="<br><br>".join(htmlBody))
            flash("Reset password instructions has been sent to your email!", "Success")
            return redirect(url_for("guestBP.login"))

        # create a token that is digitally signed with an active duration of 30 mins 
        # before it expires (something like JWT/JWS but not exactly)
        jsonPayload = {"userID": userInfo[0]}
        expiryInfo = JWTExpiryProperties(activeDuration=60*30)
        token = EC_sign(payload=jsonPayload, b64EncodeData=True, expiry=expiryInfo)
        sql_operation(
            table="one_time_use_jwt", mode="add_jwt", jwtToken=token, 
            expiryDate=expiryInfo.expiryDate.replace(microsecond=0, tzinfo=None)
        )

        # send the token to the user's email
        htmlBody = [
            "You are receiving this email due to a request to reset your password on your CourseFinity account.<br>If you did not make this request, please ignore this email.",
            f"You can change the password on your account by clicking the button below.<br><a href='{url_for('guestBP.resetPassword', token=token, _external=True)}' style='background-color:#4CAF50;width:min(250px,40%);border-radius:5px;color:white;padding:14px 25px;text-decoration:none;text-align:center;display:inline-block;' target='_blank'>Click here to reset your password</a>"
        ]
        send_email(to=emailInput, subject="Reset Password", body="<br><br>".join(htmlBody))

        flash("Reset password instructions has been sent to your email!", "Success")
        return redirect(url_for("guestBP.login"))
    else:
        return render_template("users/guest/request_password_reset.html", form=requestForm)

@guestBP.route("/reset-password/<string:token>", methods=["GET", "POST"])
def resetPassword(token:str):
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    # check if jwt exists in database
    jwtExists = sql_operation(table="one_time_use_jwt", mode="jwt_exists", jwtToken=token)
    if (not jwtExists):
        flash("Reset password link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    # verify the token
    data = EC_verify(data=token, getData=True)
    if (not data.get("verified")):
        # if the token is invalid
        flash("Reset password link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    # get the userID from the token
    jsonPayload = data["data"]["payload"]
    userID = jsonPayload["userID"]

    # check if the user exists in the database
    if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
        # if the user does not exist
        flash("Reset password link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    resetPasswordForm = CreateResetPasswordForm(request.form)

    # check if user has enabled 2FA
    try:
        twoFAToken = sql_operation(table="2fa_token", mode="get_token", userID=userID)
    except (No2FATokenError):
        twoFAToken = None
    twoFAEnabled = True if (twoFAToken is not None) else False

    if (request.method == "POST" and resetPasswordForm.validate()):
        # check if password input and confirm password are the same
        passwordInput = resetPasswordForm.password.data
        confirmPasswordInput = resetPasswordForm.cfmPassword.data
        if (passwordInput != confirmPasswordInput):
            flash("Entered passwords do not match!")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

        if (twoFAEnabled):
            # if 2FA is enabled, check if the 2FA token is valid
            twoFAInput = request.form.get("totpInput") or ""
            if (not re.fullmatch(CONSTANTS.TWO_FA_CODE_REGEX, twoFAInput) or not pyotp.TOTP(twoFAToken).verify(twoFAInput)):
                # if the 2FA token is invalid
                flash("Entered 2FA OTP is invalid or has expired!")
                return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

        if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
            flash("Password is not strong enough!", "Danger")
            return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

        # update the password
        sql_operation(table="user", mode="reset_password", userID=userID, newPassword=passwordInput)
        sql_operation(table="one_time_use_jwt", mode="delete_jwt", jwtToken=token)
        flash("Password has been reset successfully!", "Success")
        return redirect(url_for("guestBP.login"))
    else:
        return render_template("users/guest/reset_password.html", form=resetPasswordForm, twoFAEnabled=twoFAEnabled)

@guestBP.route("/login", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def login():
    if ("user" not in session or "admin" not in session):
        loginForm = CreateLoginForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/login.html", form=loginForm)

        if (request.method == "POST" and loginForm.validate()):
            requestIPAddress = get_remote_address()
            emailInput = loginForm.email.data
            passwordInput = loginForm.password.data
            recaptchaToken = request.form.get("g-recaptcha-response")
            if (recaptchaToken is not None and recaptchaToken != ""):
                try:
                    recaptchaResponse = create_assessment(siteKey=CONSTANTS.LOGIN_SITE_KEY, recaptchaToken=recaptchaToken, recaptchaAction="login")
                except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
                    flash("Please check the reCAPTCHA box and try again.", "Danger")
                    return render_template("users/guest/login.html", form=loginForm)

                if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.75)):
                    # if the score is not within the acceptable threshold
                    # then the user is likely a bot
                    # hence, we will flash an error message
                    flash("Please check the reCAPTCHA box and try again.", "Danger")
                    return render_template("users/guest/login.html", form=loginForm)
            else:
                flash("Please check the reCAPTCHA box and try again.", "Danger")
                return render_template("users/guest/login.html", form=loginForm)

            userInfo = isAdmin = successfulLogin = userHasTwoFA = False
            try:
                # returns the userID, boolean if user logged in from a new IP address, username, role
                userInfo = sql_operation(table="user", mode="login", email=emailInput, password=passwordInput, ipAddress=requestIPAddress)
                isAdmin = True if (userInfo[3] == "Admin") else False
                # raise LoginFromNewIpAddressError("test") # for testing the guard authentication process

                if (userInfo[1]):
                    # login from new ip address
                    raise LoginFromNewIpAddressError("Login from a new IP address!")

                successfulLogin = True
                sql_operation(table="login_attempts", mode="reset_user_attempts_for_user", userID=userInfo[0])

                userHasTwoFA = sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userInfo[0])
            except (IncorrectPwdError, EmailDoesNotExistError):
                try:
                    sql_operation(table="login_attempts", mode="add_attempt", email=emailInput)
                    flash("Please check your entries and try again!", "Danger")
                except (EmailDoesNotExistError):
                    flash("Please check your entries and try again!", "Danger")
                except (AccountLockedError):
                    print("Account locked")
                    flash("Too many failed login attempts, please try again later.", "Danger")
            except (AccountLockedError):
                print("Account locked")
                flash("Too many failed login attempts, please try again later.", "Danger")
            except (UserIsUsingOauth2Error):
                flash("Please check your entries and try again!", "Danger")
            except (EmailNotVerifiedError):
                flash("Please verify your email first!", "Danger")
            except (LoginFromNewIpAddressError):
                # sends an email with a generated TOTP code 
                # to authenticate the user if login was successful.
                # 640 bits/128 characters in length (5 bits per base32 character).
                # Chose the length of the code to be 824 characters
                # as it must be a multiple of 8 for the length
                # to avoid unexpected behaviour when verifying the TOTP
                # https://github.com/pyauth/pyotp/issues/115
                generatedTOTPSecretToken = pyotp.random_base32(length=128)
                generatedTOTP = pyotp.TOTP(generatedTOTPSecretToken, name=userInfo[2], issuer="CourseFinity", interval=900).now() # 15 mins

                ipDetails = CONSTANTS.IPINFO_HANDLER.getDetails(requestIPAddress).all
                # utc+8 time (SGT)
                currentDatetime = datetime.now().astimezone(tz=ZoneInfo("Asia/Singapore"))
                currentDatetime = currentDatetime.strftime("%d %B %Y %H:%M:%S %Z")

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

                messagePartList = [
                    f"Your CourseFinity account, {emailInput}, was logged in to from a new IP address.", 
                    f"Time: {currentDatetime} (SGT)<br>Location*: {locationString}<br>New IP Address: {requestIPAddress}",
                    "* Location is approximate based on the login's IP address.",
                    f"Please enter the generated code below to authenticate yourself.<br>Generated Code (will expire in 15 minutes!):<br><strong>{generatedTOTP}</strong>", 
                    f"If this was not you, we recommend that you <strong>change your password immediately</strong> by clicking the link below.<br>Change password:<br>{url_for('loggedInBP.updatePassword', _external=True)}"
                ]
                send_email(to=emailInput, subject="Unfamiliar Login Attempt", body="<br><br>".join(messagePartList))

                session["user_email"] = emailInput
                session["ip_details"] = ipDetails
                session["password_compromised"] = pwd_has_been_pwned(passwordInput)
                session["temp_uid"] = userInfo[0]
                session["username"] = userInfo[2]
                session["token"] = RSA_encrypt(generatedTOTPSecretToken)
                session["is_admin"] = isAdmin
                flash("An email has been sent to you with your special access code!", "Success")
                return redirect(url_for("guestBP.enterGuardTOTP"))

            passwordCompromised = None
            if (successfulLogin):
                # check if password has been compromised
                # if so, we will send an email to the user and flash
                # on the home page after the login process
                passwordCompromised = pwd_has_been_pwned(passwordInput)

            if (successfulLogin and not userHasTwoFA):
                session["sid"] = add_session(userInfo[0], userIP=get_remote_address())
                if (not isAdmin):
                    session["user"] = userInfo[0]
                else:
                    session["admin"] = userInfo[0]

                if (passwordCompromised):
                    send_change_password_alert_email(email=emailInput)
                    return redirect(url_for("generalBP.home"))
                return redirect(url_for("generalBP.home"))
            elif (successfulLogin and userHasTwoFA):
                # if user has 2fa enabled and is 
                # logged in from a known ip address
                session["user_email"] = emailInput
                session["password_compromised"] = passwordCompromised
                session["temp_uid"] = userInfo[0]
                session["is_admin"] = isAdmin
                return redirect(url_for("guestBP.enter2faTOTP"))
            else:
                return render_template("users/guest/login.html", form=loginForm)
        else:
            return render_template("users/guest/login.html", form = loginForm)
    else:
        return redirect(url_for("generalBP.home"))

@guestBP.route("/unlock-account/<string:token>")
def unlockAccount(token:str):
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    # check if jwt exists in database
    jwtExists = sql_operation(table="one_time_use_jwt", mode="jwt_exists", jwtToken=token)
    if (not jwtExists):
        flash("Unlock account url is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    # verify the token
    data = EC_verify(data=token, getData=True)
    if (not data.get("verified")):
        # if the token is invalid
        flash("Unlock account link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    # get the userID from the token
    jsonPayload = data["data"]["payload"]
    userID = jsonPayload["userID"]

    # check if the user exists in the database
    if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
        # if the user does not exist
        flash("Unlock account link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    sql_operation(table="login_attempts", mode="reset_user_attempts_for_user", userID=userID)
    sql_operation(table="one_time_use_jwt", mode="delete_jwt", jwtToken=token)
    flash("Your account has been unlocked! Try logging in now!", "Success")
    return redirect(url_for("guestBP.login"))

@guestBP.route("/verify-login", methods=["GET", "POST"])
def enterGuardTOTP():
    """
    This page is only accessible to users who are logging but from a new IP address.
    """
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    if (
        "user_email" not in session or
        "ip_details" not in session or
        "password_compromised" not in session or 
        "temp_uid" not in session or
        "username" not in session or
        "token" not in session or
        "is_admin" not in session
    ):
        session.clear()
        return redirect(url_for("guestBP.login"))

    if (session["ip_details"]["ip"] != get_remote_address()):
        flash("IP address does not match login request, please try again!", "Danger")
        session.clear()
        return redirect(url_for("guestBP.login"))

    guardAuthForm = twoFAForm(request.form)
    htmlTitle = "Verify Login"
    formHeader = "Verify That It's You!"
    formBody = "You are seeing this as our system have detected that you are logging in from a new IP address. Please enter the generated code that was sent to your email below to authenticate yourself."
    if (request.method == "GET"):
        return render_template("users/guest/enter_totp.html", title=htmlTitle, form=guardAuthForm, formHeader=formHeader, formBody=formBody)

    if (request.method == "POST" and guardAuthForm.validate()):
        totpInput = guardAuthForm.twoFATOTP.data
        totpSecretToken = RSA_decrypt(session["token"])
        if (not pyotp.TOTP(totpSecretToken, name=session["username"], issuer="CourseFinity", interval=900).verify(totpInput)):
            flash("Please check your entries and try again!", "Danger")
            return render_template("users/guest/enter_totp.html", title=htmlTitle, form=guardAuthForm, formHeader=formHeader, formBody=formBody)

        userID = session["temp_uid"]
        isAdmin = session["is_admin"]
        session.clear()

        sql_operation(table="user_ip_addresses", mode="add_ip_address", userID=userID, ipAddress=get_remote_address(), ipDetails=session["ip_details"])
        session["sid"] = add_session(userID, userIP=get_remote_address())

        # check if password has been compromised
        # if so, flash a message and send an email to the user
        if (session["password_compromised"]):
            send_change_password_alert_email(email=session["user_email"])

        if (isAdmin):
            session["admin"] = userID
        else:
            session["user"] = userID
        return redirect(url_for("generalBP.home"))

    # post request with invalid form values
    return render_template("users/guest/enter_totp.html", title=htmlTitle, form=guardAuthForm, formHeader=formHeader, formBody=formBody)

@guestBP.route("/login-google")
def loginViaGoogle():
    if ("user" not in session or "admin" not in session):
        # https://developers.google.com/identity/protocols/oauth2/web-server#python
        authorisationUrl, state = current_app.config["GOOGLE_OAUTH_FLOW"].authorization_url(
            # Enable offline access so that you can refresh an
            # access token without re-prompting the user for permission
            access_type="offline",

            # Enable incremental authorization
            # Recommended as a best practice according to Google documentation
            include_granted_scopes="true"
        )

        # Store the state so the callback can verify the auth server response
        session["state"] = RSA_encrypt(state)
        return redirect(authorisationUrl)
    else:
        return redirect(url_for("generalBP.home"))

@guestBP.route("/login-callback")
def loginCallback():
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    if ("state" not in session):
        return redirect(url_for("guestBP.login"))

    try:
        current_app.config["GOOGLE_OAUTH_FLOW"].fetch_token(authorization_response=request.url)
    except (Exception):
        flash("An error occurred while trying to login via Google!", "Danger")
        return redirect(url_for("guestBP.login"))

    if (RSA_decrypt(session["state"]) != request.args.get("state")):
        abort(500) # when state does not match (protect against CSRF attacks)

    credentials = current_app.config["GOOGLE_OAUTH_FLOW"].credentials
    requestSession = req.session()
    cachedSession = CacheControl(requestSession)
    tokenRequest = GoogleRequest(session=cachedSession)

    try:
        # clock_skew_in_seconds=5 seconds as it might take some time to retreive the token from Google API
        idInfo = id_token.verify_oauth2_token(credentials.id_token, tokenRequest, audience=current_app.config["GOOGLE_CLIENT_ID"], clock_skew_in_seconds=5)
    except (ValueError, GoogleAuthError):
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
    if (returnedRole != "Admin"):
        session["user"] = userID
    else:
        session["admin"] = userID

    session["sid"] = add_session(userID, userIP=get_remote_address())
    return redirect(url_for("generalBP.home"))

@guestBP.route("/signup", methods=["GET", "POST"])
def signup():
    if ("user" not in session and "admin" not in session):
        signupForm = CreateSignUpForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/signup.html", form=signupForm)

        if (request.method == "POST" and signupForm.validate()):
            # POST request code below
            recaptchaToken = request.form.get("g-recaptcha-response")
            if (recaptchaToken is not None and recaptchaToken != ""):
                try:
                    recaptchaResponse = create_assessment(siteKey=CONSTANTS.SIGNUP_SITE_KEY, recaptchaToken=recaptchaToken, recaptchaAction="signup")
                except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
                    flash("Please check the reCAPTCHA box and try again.")
                    return render_template("users/guest/signup.html", form=signupForm)

                if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.5)):
                    # if the score is not within the acceptable threshold
                    # then the user is likely a bot
                    # hence, we will flash an error message
                    flash("Please check the reCAPTCHA box and try again.")
                    return render_template("users/guest/signup.html", form=signupForm)
            else:
                flash("Please check the reCAPTCHA box and try again.")
                return render_template("users/guest/signup.html", form=signupForm)

            emailInput = signupForm.email.data
            usernameInput = signupForm.username.data
            passwordInput = signupForm.password.data
            confirmPasswordInput = signupForm.cfmPassword.data

            # some checks on the password input
            if (passwordInput != confirmPasswordInput):
                flash("Entered passwords do not match!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (len(passwordInput) < CONSTANTS.MIN_PASSWORD_LENGTH):
                flash(f"Password must be at least {CONSTANTS.MIN_PASSWORD_LENGTH} characters long!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (len(passwordInput) > CONSTANTS.MAX_PASSWORD_LENGTH):
                flash(f"Password cannot be more than {CONSTANTS.MAX_PASSWORD_LENGTH} characters long!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
                flash("Password is too weak, please enter a stronger password!")
                return render_template("users/guest/signup.html", form=signupForm)

            passwordInput = CONSTANTS.PH.hash(passwordInput)
            ipAddress = get_remote_address()

            returnedVal = sql_operation(table="user", mode="signup", email=emailInput, username=usernameInput, password=passwordInput, ipAddress=ipAddress)

            if (isinstance(returnedVal, tuple)):
                emailDupe = returnedVal[0]
                usernameDupe = returnedVal[1]
                if (emailDupe and usernameDupe):
                    flash("Email and username already exists!")
                elif (emailDupe):
                    flash("Email already exists!")
                elif (usernameDupe):
                    flash("Username already exists!")
                return render_template("users/guest/signup.html", form=signupForm)

            try:
                send_verification_email(email=emailInput, username=usernameInput, userID=returnedVal)
                flash(f"An email has bent sent to {emailInput} for you to verify your email!", "Success")
            except:
                flash(
                    Markup(f"Failed to send email! Please try again by clicking <a href='{url_for('guestBP.sendVerifyEmail') + '?user=' + returnedVal}'>me</a>!"),
                    "Danger"
                )
                return redirect(url_for("guestBP.login"))
            return redirect(url_for("guestBP.login"))
        else:
            # post request but form inputs are not valid
            return render_template("users/guest/signup.html", form=signupForm)
    else:
        return redirect(url_for("generalBP.home"))

@guestBP.route("/send-verify-email")
def sendVerifyEmail():
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    userID = request.args.get("user", default=None, type=str)
    if (userID is None):
        abort(404)

    userInfo = sql_operation(table="user", mode="get_user_data", userID=userID)
    if (userInfo and not userInfo[4]):
        email = userInfo[3]
        username = userInfo[2]
        try:
            send_verification_email(email=email, username=username, userID=userID)
            flash(f"An email has bent sent to you to verify your email!", "Success")
        except:
            flash(
                Markup(f"Failed to send email! Please try again by clicking <a href='{url_for('guestBP.sendVerifyEmail') + '?user=' + userID}'>me</a> later!"),
                "Danger"
            )
        return redirect(url_for("guestBP.login"))
    else:
        # If user does not exist or already has its email verified
        abort(404)

@guestBP.route("/verify-email/<string:token>")
def verifyEmail(token:str):
    # check if jwt exists in database
    jwtExists = sql_operation(table="one_time_use_jwt", mode="jwt_exists", jwtToken=token)
    if (not jwtExists):
        if ("user" in session):
            flash("Verify email url is invalid or has expired!", "Warning!")
            return redirect(url_for("userBP.userProfile"))
        elif ("user" not in session):
            flash("Verify email url is invalid or has expired!", "Danger")
            return redirect(url_for("guestBP.login"))

    # verify the token
    data = EC_verify(data=token, getData=True)
    if (not data.get("verified")):
        # if the token is invalid
        flash("Verify email link is invalid or has expired!", "Danger")
        return redirect(url_for("guestBP.login"))

    # get the userID from the token
    jsonPayload = data["data"]["payload"]
    userID = jsonPayload["userID"]

    # Check if user is logged in, check if the userID in the token
    # matches the userID in the session.
    if ("user" in session and session["user"] != userID):
        flash("Verify email link is invalid or has expired!", "Danger")
        return redirect(url_for("generalBP.home"))

    # check if the user exists in the database
    if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
        # if the user does not exist
        flash("Reset password link is invalid or has expired!", "Danger")
        if ("user" in session):
            session.clear()
        return redirect(url_for("guestBP.login"))

    # check if email has been verified
    if (sql_operation(table="user", mode="email_verified", userID=userID)):
        # if the email has been verified
        if ("user" in session):
            flash("Your email has already been verified!", "Sorry!")
            return redirect(url_for("generalBP.home"))
        else:
            flash("Your email has already been verified!", "Danger")
            return redirect(url_for("guestBP.login"))

    # update the email verified column to true
    sql_operation(table="user", mode="update_email_to_verified", userID=userID)
    sql_operation(table="one_time_use_jwt", mode="delete_jwt", jwtToken=token)
    if ("user" in session):
        flash("Your email has been verified!", "Email Verified!")
        return redirect(url_for("generalBP.home"))
    else:
        flash("Your email has been verified!", "Success")
        return redirect(url_for("guestBP.login"))

@guestBP.route("/enter-2fa", methods=["GET", "POST"])
def enter2faTOTP():
    """
    This page is only accessible to users who have 2FA enabled and is trying to login.
    """
    if ("user" in session or "admin" in session):
        return redirect(url_for("generalBP.home"))

    if (
        "user_email" not in session or
        "password_compromised" not in session or
        "temp_uid" not in session or
        "is_admin" not in session
    ):
        session.clear()
        return redirect(url_for("guestBP.login"))

    htmlTitle = "Enter 2FA TOTP"
    formHeader = "Enter your 2FA TOTP"
    formBody = "You are seeing this as you have enabled 2FA on your account. Please enter the 6 digit code on the Google Authenticator app installed on your phone to authenticate yourself."
    twoFactorAuthForm = twoFAForm(request.form)
    if (request.method == "GET"):
        return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm, formHeader=formHeader, formBody=formBody)

    if (request.method == "POST" and twoFactorAuthForm.validate()):
        twoFAInput = twoFactorAuthForm.twoFATOTP.data
        userID = session["temp_uid"]
        try:
            getSecretToken = sql_operation(table="2fa_token", mode="get_token", userID=userID)
        except (No2FATokenError):
            # if for whatever reasons, the user has no 2FA token (which shouldn't happen), redirect to login
            return redirect(url_for("guestBP.login"))

        if (pyotp.TOTP(getSecretToken).verify(twoFAInput)):
            isAdmin = session["is_admin"]
            if (isAdmin):
                session["admin"] = userID
            else:
                session["user"] = userID

            session["sid"] = add_session(userID, userIP=get_remote_address())

            # check if password has been compromised
            # if so, flash a message and send an email to the user
            if (session["password_compromised"]):
                send_change_password_alert_email(email=session["user_email"])

            # clear the temp_uid and temp_role
            session.pop("temp_uid", None)
            session.pop("is_admin", None)
            return redirect(url_for("generalBP.home"))
        else:
            flash("Invalid 2FA code, please try again!", "Danger")
            return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm, title=htmlTitle, formHeader=formHeader, formBody=formBody)

    # post request but form inputs are not valid
    return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm, title=htmlTitle, formHeader=formHeader, formBody=formBody)