# import third party libraries
from werkzeug.utils import secure_filename
import requests as req
from apscheduler.schedulers.background import BackgroundScheduler
from dicebear import DOptions
import pyotp, qrcode

# for Google OAuth 2.0 login (Third-party libraries)
from cachecontrol import CacheControl
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google.auth.exceptions import GoogleAuthError

# import flask libraries (Third-party libraries)
from flask import Flask, render_template, request, redirect, url_for, session, flash, Markup, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# import local python libraries
from python_files.AppFunctions import *
from python_files.NormalFunctions import *
from python_files.Forms import *
from python_files.Errors import *
from python_files.ConstantsInit import GOOGLE_CREDENTIALS, DEBUG_MODE, \
                                       FLASK_SECRET_KEY_NAME, get_secret_payload, PH, MAX_PASSWORD_LENGTH

# import python standard libraries
from datetime import datetime
from pathlib import Path
from base64 import b64encode
from io import BytesIO
from os import environ

"""Web app configurations"""
# general Flask configurations
app = Flask(__name__)

# Debug flag (will be set to false when deployed)
app.config["DEBUG_FLAG"] = DEBUG_MODE

# secret key mainly for digitally signing the session cookie
# it will retrieve the secret key from Google Secret Manager API
app.config["SECRET_KEY"] = get_secret_payload(secretID=FLASK_SECRET_KEY_NAME, decodeSecret=False)

# for other scheduled tasks such as deleting expired session id from the database
scheduler = BackgroundScheduler()

# rate limiter configuration using flask limiter
limiter = Limiter(app, key_func=get_remote_address, default_limits=["30 per second"])

# Maximum file size for uploading anything to the web app's server
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024 # 200MiB

# Configurations for dicebear api for user profile image options
app.config["DICEBEAR_OPTIONS"] = DOptions(size=250)

# for image uploads file path
app.config["PROFILE_UPLOAD_PATH"] = Path(app.root_path).joinpath("static", "images", "user")
app.config["THUMBNAIL_UPLOAD_PATH"] = Path(app.root_path).joinpath("static", "images", "courses", "thumbnails")
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ("png", "jpg", "jpeg")

# for course video uploads file path
app.config["COURSE_VIDEO_FOLDER"] = Path(app.root_path).joinpath("static", "course_videos")
app.config["ALLOWED_VIDEO_EXTENSIONS"] = (".mp4, .mov, .avi, .3gpp, .flv, .mpeg4, .flv, .webm, .mpegs, .wmv")

# database folder path
app.config["DATABASE_FOLDER"] = app.root_path + r"\databases"

# SQL database file path
app.config["SQL_DATABASE"] = app.config["DATABASE_FOLDER"] + r"\database.db"

# Session config
app.config["SESSION_EXPIRY_INTERVALS"] = 30 # 30 mins

# duration for locked accounts before user can try to login again
app.config["LOCKED_ACCOUNT_DURATION"] = 30 # 

# To allow Google OAuth2.0 to work as it will only work in https if this not set to 1/True
if (app.config["DEBUG_FLAG"]):
    environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 

"""End of Web app configurations"""

@app.before_first_request
def before_first_request() -> None:
    """
    Called called at the very first request to the web app.
    
    Returns:
    - None
    """
    # get ip address blacklist from a github repo or the saved file
    app.config["IP_ADDRESS_BLACKLIST"] = get_IP_address_blacklist()

    # load google client id from credentials.json
    app.config["GOOGLE_CLIENT_ID"] = GOOGLE_CREDENTIALS["web"]["client_id"]

    # get Google oauth flow object
    app.config["GOOGLE_OAUTH_FLOW"] = get_google_flow()

@app.before_request
def before_request() -> None:
    """
    Called before each request to the web app.
    
    Returns:
    - None
    """
    if (get_remote_address() in app.config["IP_ADDRESS_BLACKLIST"]):
        abort(403)

def validate_session() -> None:
    """
    Validates the session if user is logged in.
    
    Used at every route functions.
    
    Returns
    - None
    """
    if (("user" in session) ^ ("admin" in session)):
        # if either user or admin is in the session cookie value
        userID = session.get("user") or session.get("admin")
        try:
            sessionID = RSA_decrypt(session["sid"])
        except (DecryptionError):
            session.clear()
            abort(500)

        if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
            # if user session is invalid as the user does not exist anymore
            sql_operation(table="session", mode="delete_session", sessionID=sessionID)
            session.clear()
            return

        if (sql_operation(table="session", mode="if_session_exists", sessionID=sessionID)):
            # if session exists
            if (not sql_operation(table="session", mode="check_if_valid", sessionID=sessionID, userID=userID)):
                # if user session is expired or the userID does not match with the sessionID
                sql_operation(table="session", mode="delete_session", sessionID=sessionID)
                session.clear()
                return

            # update session expiry time
            sql_operation(table="session", mode="update_session", sessionID=sessionID)
            return
        else:
            # if session does not exist in the db
            session.clear()
            return
    elif ("user" in session and "admin" in session):
        # both user and admin are in session cookie value
        # clear the session as it should not be possible to have both session
        session.clear()

@app.after_request # called after each request to the application
def add_header(response):
    """
    Add headers to cache the rendered page for 10 minutes.
    
    Note that max-age is for the browser, s-maxage is for the CDN.
    It will be useful when the flask web app is deployed to a server.
    This helps to reduce loads on the flask webapp such that the server can handle more requests
    as it doesn't have to render the page again for each request to the application.
    """
    # it is commented out as we are still developing the web app and it is not yet ready to be hosted.
    # will be uncommented when the web app is ready to be hosted on firebase.
    # response.headers["Cache-Control"] = "public, max-age=600, s-maxage=600"
    return response

@app.route("/")
def home():
    validate_session()
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses")
    threeHighlyRatedCourses = sql_operation(table="course", mode="get_3_highly_rated_courses")

    userPurchasedCourses = []
    accType = imageSrcPath = None
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo[-1]
        accType = userInfo[1]
    elif ("admin" in session):
        accType = "Admin"

    return render_template("users/general/home.html", imageSrcPath=imageSrcPath,   
        userPurchasedCourses=userPurchasedCourses,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses), accType=accType)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("2 per second")
def login():
    validate_session()
    if ("user" not in session):
        loginForm = CreateLoginForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/login.html", form=loginForm)

        if (request.method == "POST" and loginForm.validate()):
            requestIPAddress = get_remote_address()
            emailInput = loginForm.email.data
            passwordInput = loginForm.password.data

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
                sql_operation(table="login_attempts", mode="reset_user_attempts", userID=userInfo[0])

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
            except (LoginFromNewIpAddressError):
                # sends an email with a generated TOTP code to authenticate the user
                # 1025 bits/205 characters in length (5 bits per base32 character)
                generatedTOTPSecretToken = pyotp.random_base32(length=205) 
                generatedTOTP = pyotp.TOTP(generatedTOTPSecretToken, name=userInfo[2], issuer="CourseFinity", interval=900).now() # 15 mins

                messagePartList = [f"Your CourseFinity account, {emailInput}, was logged in to from a new IP address ({requestIPAddress}).", f"Please enter the generated code below to authenticate yourself.<br>Generated Code (will expire in 15 minutes!):<br><strong>{generatedTOTP}</strong>", f"If this was not you, we recommend that you <strong>change your password immediately</strong> by clicking the link below.<br>Change password:<br>{url_for('updatePassword', _external=True)}"]
                send_email(to=emailInput, subject="Unfamiliar Login Attempt", body="<br><br>".join(messagePartList))

                session["temp_uid"] = userInfo[0]
                session["username"] = userInfo[2]
                session["token"] = RSA_encrypt(generatedTOTPSecretToken)
                session["is_admin"] = isAdmin
                flash("An email has been sent to you with your special access code!", "Success")
                return redirect(url_for("enterGuardTOTP"))

            if (successfulLogin and not userHasTwoFA):
                session["sid"] = RSA_encrypt(add_session(userInfo[0]))
                if (not isAdmin):
                    session["user"] = userInfo[0]
                else:
                    session["admin"] = userInfo[0]
                return redirect(url_for("home"))
            elif (successfulLogin and userHasTwoFA):
                session["temp_uid"] = userInfo[0]
                session["is_admin"] = isAdmin
                return redirect(url_for("enter2faTOTP"))
            else:
                return render_template("users/guest/login.html", form=loginForm)
        else:
            return render_template("users/guest/login.html", form = loginForm)
    else:
        return redirect(url_for("home"))

@app.route("/verify-login", methods=["GET", "POST"])
def enterGuardTOTP():
    """
    This page is only accessible to users who are logging but from a new IP address.
    """
    validate_session()
    if ("user" in session):
        return redirect(url_for("home"))

    if ("temp_uid" not in session or "token" not in session or "is_admin" not in session):
        return redirect(url_for("login"))

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

        sql_operation(table="user_ip_addresses", mode="add_ip_address", userID=userID, ipAddress=get_remote_address())
        session["sid"] = RSA_encrypt(add_session(userID))

        if (isAdmin):
            session["admin"] = userID
        else:
            session["user"] = userID
        return redirect(url_for("home"))

    # post request with invalid form values
    return render_template("users/guest/enter_totp.html", title=htmlTitle, form=guardAuthForm, formHeader=formHeader, formBody=formBody)

@app.route("/login-google")
def loginViaGoogle():
    validate_session()
    if ("user" not in session or "admin" not in session):
        # https://developers.google.com/identity/protocols/oauth2/web-server#python
        authorisationUrl, state = app.config["GOOGLE_OAUTH_FLOW"].authorization_url(
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
        return redirect(url_for("home"))

@app.route("/login-callback")
def loginCallback():
    validate_session()
    if ("user" in session or "admin" in session):
        return redirect(url_for("home"))

    if ("state" not in session):
        return redirect(url_for("login"))

    app.config["GOOGLE_OAUTH_FLOW"].fetch_token(authorization_response=request.url)
    if (RSA_decrypt(session["state"]) != request.args.get("state")):
        abort(500) # when state does not match (protect against CSRF attacks)

    credentials = app.config["GOOGLE_OAUTH_FLOW"].credentials
    requestSession = req.session()
    cachedSession = CacheControl(requestSession)
    tokenRequest = GoogleRequest(session=cachedSession)

    try:
        # clock_skew_in_seconds=30 seconds as it might take some time to retreive the token from Google API
        idInfo = id_token.verify_oauth2_token(credentials.id_token, tokenRequest, audience=app.config["GOOGLE_CLIENT_ID"], clock_skew_in_seconds=30) 
    except (ValueError, GoogleAuthError):
        flash("Failed to verify Google login! Please try again!", "Danger")
        return redirect(url_for("login"))

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

    session["sid"] = RSA_encrypt(add_session(userID))
    return redirect(url_for("home"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    validate_session()
    if ("user" not in session):
        signupForm = CreateSignUpForm(request.form)
        if (request.method == "GET"):
            return render_template("users/guest/signup.html", form=signupForm)

        if (request.method == "POST" and signupForm.validate()):
            # POST request code below
            emailInput = signupForm.email.data
            usernameInput = signupForm.username.data
            passwordInput = signupForm.password.data
            confirmPasswordInput = signupForm.cfm_password.data

            """
            Software Data Integrity, encrypt the email & username?
            Includes encrypting when updating in later functions
            """

            # some checks on the password input
            if (passwordInput != confirmPasswordInput):
                flash("Passwords did not match!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (len(passwordInput) < 10):
                flash("Password must be at least 10 characters long!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (len(passwordInput) > MAX_PASSWORD_LENGTH):
                flash(f"Password cannot be more than {MAX_PASSWORD_LENGTH} characters long!")
                return render_template("users/guest/signup.html", form=signupForm)
            if (pwd_has_been_pwned(passwordInput) or not pwd_is_strong(passwordInput)):
                flash("Password is too weak, please enter a stronger password!")
                return render_template("users/guest/signup.html", form=signupForm)

            passwordInput = PH.hash(passwordInput)
            ipAddress = get_remote_address()
            # print(f"username: {usernameInput}, email: {emailInput}, password: {passwordInput}, ip: {ipAddress}")

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

            session["user"] = returnedVal # i.e. successful signup, returned the user ID
            session["sid"] = RSA_encrypt(add_session(returnedVal))

            return redirect(url_for("home"))

        # post request but form inputs are not valid
        return render_template("users/guest/signup.html", form=signupForm)
    else:
        return redirect(url_for("home"))

@app.route("/logout")
def logout():
    validate_session()
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("login"))

    sql_operation(table="session", mode="delete_session", sessionID=RSA_decrypt(session["sid"]))
    session.clear()
    flash("You have successfully logged out.", "You have logged out!")
    return redirect(url_for("home"))

@app.route("/enter-2fa", methods=["GET", "POST"])
def enter2faTOTP():
    """
    This page is only accessible to users who have 2FA enabled and is trying to login.
    """
    validate_session()
    if ("user" in session or "admin" in session):
        return redirect(url_for("home"))

    if ("temp_uid" not in session and "is_admin" not in session):
        return redirect(url_for("login"))

    htmlTitle = "Enter 2FA OTP"
    formHeader = "Enter your 2FA OTP"
    twoFactorAuthForm = twoFAForm(request.form)
    if (request.method == "GET"):
        return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm, formHeader=formHeader)

    if (request.method == "POST" and twoFactorAuthForm.validate()):
        twoFAInput = twoFactorAuthForm.twoFATOTP.data
        userID = session["temp_uid"]
        try:
            getSecretToken = sql_operation(table="2fa_token", mode="get_token", userID=userID)
        except (No2FATokenError):
            # if for whatever reasons, the user has no 2FA token (which shouldn't happen), redirect to login
            return redirect(url_for("login"))

        if (pyotp.TOTP(getSecretToken).verify(twoFAInput)):
            isAdmin = session["is_admin"]
            if (isAdmin):
                session["admin"] = userID
            else:
                session["user"] = userID

            session["sid"] = RSA_encrypt(add_session(userID))

            # clear the temp_uid and temp_role
            session.pop("temp_uid", None)
            session.pop("is_admin", None)
            return redirect(url_for("home"))
        else:
            flash("Invalid 2FA code, please try again!", "Danger")
            return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm, title=htmlTitle, formHeader=formHeader)

    # post request but form inputs are not valid
    return render_template("users/guest/enter_totp.html", form=twoFactorAuthForm, title=htmlTitle, formHeader=formHeader)

@app.post("/disable-2fa")
def disableTwoFactorAuth():
    validate_session()
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("login"))

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
        return redirect(url_for("userProfile"))

    if (sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userID)):
        sql_operation(table="2fa_token", mode="delete_token", userID=userID)
        flash(Markup("Two factor authentication has been <span class='text-danger'>disabled</span>!<br>You will no longer be prompted to enter your 2FA time-based OTP."), "2FA Disabled!")
    else:
        flash("You do not have 2FA enabled!", "2FA Is NOT Enabled!")

    return redirect(url_for("userProfile"))

@app.route("/setup-2fa", methods=["GET", "POST"])
def twoFactorAuthSetup():
    validate_session()
    if ("user" not in session and "admin" not in session):
        return redirect(url_for("login"))

    if ("user" in session):
        userID = session["user"]
    elif ("admin" in session):
        userID = session["admin"]
    imageSrcPath, userInfo = get_image_path(userID, returnUserInfo=True)

    # check if user logged in via Google OAuth2
    try:
        loginViaGoogle = sql_operation(table="user", mode="check_if_using_google_oauth2", userID=userInfo[0])
    except (UserDoesNotExist):
        abort(403) # if for whatever reason, a user does not exist, abort

    if (loginViaGoogle):
        # if so, redirect to user profile as the authentication security is handled by Google themselves
        return redirect(url_for("userProfile"))

    twoFactorAuthForm = twoFAForm(request.form)
    if (request.method == "GET"):

        # for google authenticator setup key (20 byte)
        secretToken = pyotp.random_base32() # MUST be kept secret

        imageSrcPath = get_image_path(session["user"])

        # generate a QR code for the user to scan
        totp = pyotp.totp.TOTP(s=secretToken, digits=6).provisioning_uri(name=userInfo[2], issuer_name="CourseFinity")

        # to save the image in the memory buffer
        # instead of saving the qrcode png as a file in the web server
        stream = BytesIO() 

        # create a qrcode object
        qrCodeData = qrcode.make(totp, box_size=15)

        # save the qrcode image in the memory buffer
        qrCodeData.save(stream)

        # get the image from the memory buffer and encode it into base64
        qrCodeEncodedBase64 = b64encode(stream.getvalue()).decode()

        return render_template("users/loggedin/2fa.html", form=twoFactorAuthForm, imageSrcPath=imageSrcPath, qrCodeEncodedBase64=qrCodeEncodedBase64, secretToken=secretToken, accType=userInfo[1])

    if (request.method == "POST" and twoFactorAuthForm.validate()):
        # POST request code below
        twoFATOTP = twoFactorAuthForm.twoFATOTP.data
        secretToken = request.form.get("secretToken")
        if (secretToken is None or not two_fa_token_is_valid(secretToken)):
            flash("Please check your entry and try again!")
            return redirect(url_for("twoFactorAuthSetup"))

        # check if the TOTP is valid
        if (pyotp.TOTP(secretToken).verify(twoFATOTP)):
            # update the user's 2FA status to True
            sql_operation(table="2fa_token", mode="add_token", userID=userInfo[0], token=secretToken)
            flash(Markup("2FA has been <span class='text-success'>enabled</span> successfully!<br>You will now be prompted to key in your time-based OTP whenever you login now!"), "2FA has been enabled!")
            return redirect(url_for("userProfile"))
        else:
            flash("Please check your entry and try again!")
            return redirect(url_for("twoFactorAuthSetup"))

    # post request but form inputs are not valid
    return redirect(url_for("twoFactorAuthSetup"))

@app.route("/payment-settings", methods=["GET", "POST"])
def paymentSettings():
    validate_session()
    if ("user" not in session):
        return redirect(url_for("login"))

    userID = session["user"]
    try:
        cardExists = sql_operation(table="user", mode="check_card_if_exist", userID=userID, getCardInfo=True)
        print(cardExists)
    except (CardDoesNotExistError):
        cardExists = False

    paymentForm = CreateAddPaymentForm(request.form)

    # GET method codes below
    if (request.method == "GET"):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)

        cardName = cardNumber = cardExpiry = None
        if (cardExists):
            cardInfo = cardExists[0]
            cardName = cardInfo[0]
            cardNumber = cardInfo[1]
            cardExpiry = cardInfo[2]

        return render_template("users/loggedin/payment_settings.html", form=paymentForm, imageSrcPath=imageSrcPath, cardExists=cardExists, cardName=cardName, cardNo=cardNumber, cardExpiry=cardExpiry, accType=userInfo[1])

    # POST method codes below
    if (paymentForm.validate() and not cardExists):
        # POST request code below
        cardNumberInput = paymentForm.cardNo.data
        cardNameInput = paymentForm.cardName.data
        cardExpiryInput = paymentForm.cardExpiry.data

        sql_operation(table="user", mode="add_card", userID=userID, cardNo=cardNumberInput, cardName=cardNameInput, cardExpiry=cardExpiryInput)
        return redirect(url_for("paymentSettings"))

    # invalid form inputs or already has a card
    return redirect(url_for("paymentSettings"))

@app.post("/delete-payment")
def deletePayment():
    validate_session()
    if ("user" not in session):
        return redirect(url_for("login"))

    userID = session["user"]
    cardExists = sql_operation(table="user", mode="check_card_if_exist", userID=userID)
    if (not cardExists):
        return redirect(url_for("paymentSettings"))

    sql_operation(table="user", mode="delete_card", userID=userID)
    return redirect(url_for("paymentSettings"))

@app.route("/edit-payment", methods=["GET", "POST"])
def editPayment():
    validate_session()
    if ("user" not in session):
        return redirect(url_for("login"))

    userID = session["user"]
    cardExists = sql_operation(table="user", mode="check_card_if_exist", userID=userID, getCardInfo=True)
    if (not cardExists):
        return redirect(url_for("paymentSettings"))

    editPaymentForm = CreateEditPaymentForm(request.form)

    if (request.method == "GET"):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        cardInfo = cardExists[0]
        cardName = cardInfo[0]
        cardExpiry = cardInfo[2]

        return render_template("users/loggedin/edit_payment.html", form=editPaymentForm, imageSrcPath=imageSrcPath, cardName=cardName, cardExpiry=cardExpiry, accType=userInfo[1])

    if (editPaymentForm.validate()):
        # POST request code below
        cardExpiryInput = editPaymentForm.cardExpiry.data

        sql_operation(table="user", mode="update_card", userID=userID, cardExpiry=cardExpiryInput)
        return redirect(url_for("paymentSettings"))

    # invalid form inputs
    return redirect(url_for("paymentSettings"))

@app.route("/user-profile", methods=["GET","POST"])
def userProfile():
    validate_session()
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)

        username = userInfo[2]
        email = userInfo[3]
        loginViaGoogle = True if (userInfo[4] is None) else False # check if the password is NoneType

        twoFAEnabled = False
        if (not loginViaGoogle):
            twoFAEnabled = sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userInfo[0])

        """
        Updates to teacher but page does not change, requires refresh
        """

        return render_template("users/loggedin/user_profile.html", username=username, email=email, imageSrcPath=imageSrcPath, twoFAEnabled=twoFAEnabled, loginViaGoogle=loginViaGoogle, accType=userInfo[1])
    else:
        return redirect(url_for("login"))

@app.route("/change_username", methods=["GET","POST"])
def updateUsername():
    validate_session()
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]

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
                return redirect(url_for("userProfile"))
            else:
                return render_template("users/loggedin/change_username.html", form=create_update_username_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
        else:
            return render_template("users/loggedin/change_username.html", form=create_update_username_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("login"))

@app.route("/change-email", methods=["GET","POST"])
def updateEmail():
    validate_session()
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]
        oldEmail = userInfo[2]

        # check if user logged in via Google OAuth2
        loginViaGoogle = True if (userInfo[4] is None) else False
        if (loginViaGoogle):
            # if so, redirect to user profile as they cannot change their email
            return redirect(url_for("userProfile"))

        create_update_email_form = CreateChangeEmail(request.form)
        if (request.method == "POST") and (create_update_email_form.validate()):
            updatedEmail = create_update_email_form.updateEmail.data
            currentPassword = create_update_email_form.currentPassword.data

            changed = False
            try:
                sql_operation(table="user", mode="change_email", userID=userID, email=updatedEmail, currentPassword=currentPassword)
                changed = True
            except (EmailAlreadyInUseError):
                flash("Sorry, email has already been taken!")
            except (SameAsOldEmailError):
                flash("Sorry, please enter a different email from your current one!")
            except (IncorrectPwdError):
                flash("Sorry, please check your current password and try again!")

            if (not changed):
                return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
            else:
                print(f"old email:{oldEmail}, new email:{updatedEmail}")
                flash("Your email has been successfully changed.", "Account Details Updated!")
                return redirect(url_for("userProfile"))
        else:
            return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("login"))

@app.route("/change-password", methods=["GET","POST"])
def updatePassword():
    validate_session()
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userID = userInfo[0]

        # check if user logged in via Google OAuth2
        loginViaGoogle = True if (userInfo[4] is None) else False
        if (loginViaGoogle):
            # if so, redirect to user profile as they cannot change their password
            return redirect(url_for("userProfile"))

        create_update_password_form = CreateChangePasswordForm(request.form)
        if (request.method == "POST") and (create_update_password_form.validate()):
            currentPassword = create_update_password_form.currentPassword.data
            updatedPassword = create_update_password_form.updatePassword.data
            confirmPassword = create_update_password_form.confirmPassword.data

            if (updatedPassword != confirmPassword):
                flash("Passwords Do Not Match!")
                return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
            else:
                changed = False
                try:
                    sql_operation(table="user", mode="change_password", userID=userID, password=updatedPassword, oldPassword=currentPassword)
                    changed = True
                except (ChangePwdError):
                    flash("Please check your entries and try again.")
                except (PwdTooShortError, PwdTooLongError):
                    flash(f"Password must be between 10 and {MAX_PASSWORD_LENGTH} characters long.")
                except (PwdTooWeakError):
                    flash("Password is too weak, please enter a stronger password!")

                if (changed):
                    flash("Your password has been successfully changed.", "Account Details Updated!")
                    return redirect(url_for("userProfile"))
                else:
                    return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
        else:
            return render_template("users/loggedin/change_password.html", form=create_update_password_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("login"))

@app.post("/change-account-type")
def changeAccountType():
    validate_session()
    if ("user" in session):
        userID = session["user"]
        if (request.form["changeAccountType"] == "changeToTeacher"):
            try:
                sql_operation(table="user", mode="update_to_teacher", userID=userID)
                flash("Your account has been successfully upgraded to a Teacher.", "Account Details Updated!")
            except (IsAlreadyTeacherError):
                flash("You are already a teacher!", "Failed to Update!")
            return redirect(url_for("userProfile"))
        else:
            print("Did not have relevant hidden field.")
            return redirect(url_for("userProfile"))
    else:
        return redirect(url_for("login"))

@app.post("/delete-profile-picture")
def deletePic():
    validate_session()
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        if ("https" not in imageSrcPath):
            fileName = imageSrcPath.rsplit("/", 1)[-1]
            Path(app.config["PROFILE_UPLOAD_PATH"]).joinpath(fileName).unlink(missing_ok=True)
            sql_operation(table="user", mode="delete_profile_picture", userID=userInfo[0])
            flash("Your profile picture has been successfully deleted.", "Profile Picture Deleted!")
        return redirect(url_for("userProfile"))
    else:
        return redirect(url_for("login"))

@app.post("/upload-profile-picture")
def uploadPic():
    validate_session()
    if ("user" in session):
        userID = session["user"]
        if ("profilePic" not in request.files):
            print("No File Sent")
            return redirect(url_for("userProfile"))

        file = request.files["profilePic"]
        filename = file.filename
        if (filename.strip() == ""):
            abort(500)

        if (not accepted_image_extension(filename)):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Profile Image!")
            return redirect(url_for("userProfile"))

        filename = f"{userID}.webp"
        print(f"This is the filename for the inputted file : {filename}")

        filePath = app.config["PROFILE_UPLOAD_PATH"].joinpath(filename)
        print(f"This is the filepath for the inputted file: {filePath}")

        imageData = BytesIO(file.read())
        compress_and_resize_image(imageData=imageData, imagePath=filePath, dimensions=(500, 500))

        imageUrlToStore = url_for("static", filename=f"images/user/{filename}")
        sql_operation(table="user", mode="change_profile_picture", userID=userID, profileImagePath=imageUrlToStore)

        return redirect(url_for("userProfile"))
    else:
        return redirect(url_for("login"))

@app.route("/video-upload", methods=["GET", "POST"])
def videoUpload():
    validate_session()
    if ("user" in session):
        courseID = generate_id()
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        if (userInfo[1] != "Teacher"):
            abort(500)

        if (request.method == "POST"):
            if (request.files["courseVideo"].filename == ""):
                flash("Please Upload a Video")
                return redirect(url_for("videoUpload"))
            
            file = request.files.get("courseVideo")
            filename = secure_filename(file.filename)

            print(f"This is the filename for the inputted file : {filename}")

            filePath = Path(app.config["COURSE_VIDEO_FOLDER"]).joinpath(courseID)
            print(f"This is the folder for the inputted file: {filePath}")
            filePath.mkdir(parents=True, exist_ok=True)

            filePathToStore  = url_for("static", filename=f"course_videos/{courseID}/{filename}")
            file.save(Path(filePath).joinpath(filename))
            
            session["course-data"] = (courseID, filePathToStore)
            return redirect(url_for("createCourse"))
        else:
            return render_template("users/teacher/video_upload.html",imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("login"))

"""
Software data integrity

Why : Hackers can edit videos and prevent availability to wanted resources
solution : Encrypt video data
"""
@app.route("/create-course", methods=["GET","POST"])
def createCourse():
    validate_session()
    if ("user" in session):
        if ("course-data" in session):
            courseData = session["course-data"]
            imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
            if (userInfo[1] != "Teacher"):
                abort(500)

            courseForm = CreateCourse(request.form)
            if (request.method == "POST"):
                courseTitle = courseForm.courseTitle.data
                courseDescription = courseForm.courseDescription.data
                courseTagInput = request.form.get("courseTag")
                coursePrice = float(courseForm.coursePrice.data)

                file = request.files.get("courseThumbnail")
                filename = file.filename
                if (filename.strip() == ""):
                    abort(500)

                filename = f"{courseData[0]}.webp"
                print(f"This is the filename for the inputted file : {filename}")

                filePath = Path(app.config["THUMBNAIL_UPLOAD_PATH"]).joinpath(courseData[0])
                print(f"This is the Directory for the inputted file: {filePath}")
                filePath.mkdir(parents=True, exist_ok=True)

                imageData = BytesIO(file.read())
                compress_and_resize_image(imageData=imageData, imagePath=Path(filePath).joinpath(filename), dimensions=(1920, 1080))

                imageUrlToStore = (f"{courseData[0]}/{filename}")

                # print(f"This is the filename for the inputted file : {filename}")
                # filePath = Path(app.config["THUMBNAIL_UPLOAD_PATH"]).joinpath(filename)
                # print(f"This is the filePath for the inputted file: {filePath}")            
                # file.save(filePath)

                sql_operation(table="course", mode="insert",courseID=courseData[0], teacherId=userInfo[0], courseName=courseTitle, courseDescription=courseDescription, courseImagePath=imageUrlToStore, courseCategory=courseTagInput, coursePrice=coursePrice, videoPath=courseData[1])

                session.pop("course-data")
                flash("Course Created")
                return redirect(url_for("userProfile"))
            else:
                return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1])
        else:
            flash("No Video Uploaded")
            return redirect(url_for("videoUpload"))
    else:
        return redirect(url_for("login"))

@app.route("/teacher/<teacherID>")
def teacherPage(teacherID):
    validate_session()
    latestThreeCourses = sql_operation(table="course", mode="get_3_latest_courses", teacherID=teacherID, getTeacherUsername=False)
    threeHighlyRatedCourses, teacherUsername = sql_operation(table="course", mode="get_3_highly_rated_courses", teacherID=teacherID, getTeacherUsername=True)

    teacherProfilePath = get_image_path(teacherID)

    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo[-1]
        accType = userInfo[1]

    return render_template("users/general/teacher_page.html",                              
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherUsername=teacherUsername, 
        teacherProfilePath=teacherProfilePath,
        threeHighlyRatedCourses=threeHighlyRatedCourses, threeHighlyRatedCoursesLen=len(threeHighlyRatedCourses),
        latestThreeCourses=latestThreeCourses, latestThreeCoursesLen=len(latestThreeCourses), accType=accType)

@app.route("/course/<courseID>")
def coursePage(courseID):
    validate_session()
    print(courseID)
    #courseID = "a78da127690d40d4bebaf5d9c45a09a8"
    # the course id is 
    #   a78da127690d40d4bebaf5d9c45a09a8
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    # courseName = courses[0][1]
    # print(courses)
    if courses == False: #raise exception
        abort(404)
    #create variable to store these values
    teacherID = courses[1]
    courseName = courses[2]
    courseDescription = courses[3]
    coursePrice = courses[5]
    courseCategory = courses[6]
    courseRating = courses[7]
    courseRatingCount = courses[8]
    courseDate = courses[9]
    courseVideoPath = courses[10]

    print("course",courses[1])

    teacherProfilePath = get_image_path(teacherID)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=teacherID, )
    print(teacherRecords)
    teacherName = teacherRecords[2]


    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo[-1]
        accType = userInfo[1]

    return render_template("users/general/course_page.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherName, teacherProfilePath=teacherProfilePath \
        , courseID=courseID, courseName=courseName, courseDescription=courseDescription, coursePrice=coursePrice, courseCategory=courseCategory, \
        courseRating=courseRating, courseRatingCount=courseRatingCount, courseDate=courseDate, courseVideoPath=courseVideoPath, accType=accType)

@app.route("/course-review/<courseID>")
def courseReview(courseID):
    validate_session()
    accType = imageSrcPath = None
    userPurchasedCourses = {}
    courses = sql_operation(table="course", mode="", courseID=courseID)
    
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])
        accType = userInfo[1]

    return render_template("users/general/course_page_review.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, courseID=courseID, accType=accType)

@app.route("/purchase-view/<courseID>")
def purchaseView(courseID):
    validate_session()
    print(courseID)
    #courseID = "a78da127690d40d4bebaf5d9c45a09a8"
    # the course id is 
    #   a78da127690d40d4bebaf5d9c45a09a8
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    #courseName = courses[0][1]
    if courses == False: #raise 404 error
        abort(404)

    #create variable to store these values
    teacherID = courses[1]
    courseName = courses[2]
    courseDescription = courses[3]
    coursePrice = courses[5]
    courseCategory = courses[6]
    courseRating = courses[7]
    courseRatingCount = courses[8]
    courseDate = courses[9]
    courseVideoPath = courses[10]

    print("course",courses[1])

    teacherProfilePath = get_image_path(teacherID)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=teacherID)
    print(teacherRecords)
    teacherName = teacherRecords[2]


    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo[-1]
        accType = userInfo[1]

    return render_template("users/general/purchase_view.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherName, teacherProfilePath=teacherProfilePath \
        , courseID=courseID, courseName=courseName, courseDescription=courseDescription, coursePrice=coursePrice, courseCategory=courseCategory, \
        courseRating=courseRating, courseRatingCount=courseRatingCount, courseDate=courseDate, courseVideoPath=courseVideoPath, accType=accType)

@app.post("/add_to_cart/<courseID>")
def addToCart(courseID):
    validate_session()
    if ("user" in session):
        sql_operation(table="user", mode="add_to_cart", userID=session["user"], courseID=courseID)
        return redirect(url_for("cart"))
    else:
        return redirect(url_for("login"))

@app.route("/shopping_cart", methods=["GET", "POST"])
def cart():
    validate_session()
    if "user" in session:
        userID = session["user"]
        if request.method == "POST":
            # Remove item from cart
            courseID = request.form.get("courseID")
            sql_operation(table="user", mode="remove_from_cart", userID=userID, courseID=courseID)

            return redirect(url_for("cart"))

        else:
            imageSrcPath, userInfo = get_image_path(userID, returnUserInfo=True)
            cartCourseIDs = userInfo[-2]
            # print(cartCourseIDs)
            
            courseList = []
            subtotal = 0

            for courseID in cartCourseIDs:
                
                course = sql_operation(table="course", mode="get_course_data", courseID=courseID)

                courseList.append({"courseID" : course[0],
                                   "courseOwnerLink" : url_for("teacherPage", teacherID=course[1]), # course[1] is teacherID
                                   "courseOwnerUsername" : sql_operation(table="user", mode="get_user_data", userID=course[1])[2],
                                   "courseOwnerImagePath" : get_image_path(course[1]),
                                   "courseName" : course[2],
                                   "courseDescription" : course[3],
                                   "courseThumbnailPath" : course[4],
                                   "coursePrice" : f"{course[5]:,.2f}",
                                 })

                subtotal += course[5]

            return render_template("users/loggedin/shopping_cart.html", courseList=courseList, subtotal=f"{subtotal:,.2f}", imageSrcPath=imageSrcPath, accType=userInfo[1])

    else:
        return redirect(url_for("login"))

@app.route("/checkout", methods = ["GET", "POST"])
def checkout():
    validate_session()
    if "user" in session:

        userID = session["user"]

        if request.method == "POST":
            cardNo = request.form.get("cardNo")
            cardExpiryMonth  = request.form.get('cardExpMonth')
            cardExpiryYear = request.form.get('cardExpYear')
            cardCVV = request.form.get("cardCVV")
            cardName = request.form.get("cardName")
            cardSave = request.form.get("cardSave")
            print(cardCVV)

            cardErrors = []

            if cardNo == "":
                cardErrors.append('cardNo')
            if cardExpiryMonth == "":
                cardErrors.append('cardExpiryMonth')
            if cardExpiryYear == "":
                cardErrors.append('cardExpiryYear')
            if cardCVV == "":
                cardErrors.append('cardCVV')
            if cardName == "":
                cardErrors.append('cardName')

            session['cardErrors'] = cardErrors

            cardExpiry = f"{cardExpiryMonth}-{cardExpiryYear}"

            print(cardExpiryMonth)
            print(cardExpiryYear)

            # Errors, try again.
            if cardErrors != []:
                return redirect(url_for("checkout"))

            else:

                if cardSave != None:
                    sql_operation(table="user", mode="edit", userID=userID, cardNo=cardNo, cardExpiry=cardExpiry, cardCVV=cardCVV, cardName=cardName)

                # Make Purchase
                # sql_operation(table="user", mode="purchase_courses", userID=userID)

                return redirect(url_for("purchaseHistory"))

        else:
            userInfo = sql_operation(table="user", mode="get_user_data", userID=userID)

            cardInfo = {"cardName": "",
                        "cardNo": "",
                        "cardExpMonth": "",
                        "cardExpYear": "",
                        "cardCVV": ""
                        }

            if userInfo[7] is not None:

                cardInfo["cardName"] = userInfo[7]
                cardInfo["cardNo"] = userInfo[8]
                cardInfo["cardExpMonth"] = int(userInfo[9].split("-")[0])
                cardInfo["cardExpYear"] = int(userInfo[9].split("-")[1])
                cardInfo["cardCVV"] = userInfo[10]

            cartCourseIDs = sql_operation(table="user", mode="get_user_cart", userID=userID)
            cartCount = len(cartCourseIDs)

            subtotal = 0

            for courseID in cartCourseIDs:
                course = sql_operation(table="course", mode="get_course_data", courseID=courseID)
                subtotal += course[5]

            currentYear = datetime.today().year

            if "cardErrors" not in session:
                cardErrors = []
            else:
                try:
                    cardErrors = session['cardErrors']
                except (DecryptionError):
                    session.pop("cardErrors", None)
                    abort(500)

            print(cardErrors)

            return render_template("users/loggedin/checkout.html", cardErrors=cardErrors , cartCount=cartCount, subtotal=f"{subtotal:,.2f}", cardInfo=cardInfo, currentYear=currentYear, imageSrcPath=get_image_path(session["user"]), accType=userInfo[1])

    else:
        return redirect(url_for("login"))

@app.route("/purchase_history")
def purchaseHistory():
    validate_session()
    imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
    purchasedCourseIDs = userInfo[-1]
    courseList = []

    for courseID in purchasedCourseIDs:

        course = sql_operation(table="course", mode="get_course_data", courseID=courseID)

        courseList.append({"courseID" : course[0],
                            "courseOwnerLink" : url_for("teacherPage", teacherID=course[1]), # course[1] is teacherID
                            "courseOwnerUsername" : sql_operation(table="user", mode="get_user_data", userID=course[1])[2],
                            "courseOwnerImagePath" : get_image_path(course[1]),
                            "courseName" : course[2],
                            "courseDescription" : course[3],
                            "courseThumbnailPath" : course[4],
                            "coursePrice" : f"{course[5]:,.2f}",
                            })

    return render_template("users/loggedin/purchase_history.html", courseList=courseList, imageSrcPath=imageSrcPath, accType=userInfo[1])

@app.route("/purchase-view/<courseID>")
def purchaseDetails(courseID):
    validate_session()
    return render_template("users/loggedin/purchase_view.html", courseID=courseID)

@app.route("/search", methods=["GET","POST"])
def search():
    validate_session()
    searchInput = str(request.args.get("q"))
    foundResults = sql_operation(table="course", mode="search", searchInput=searchInput)

    accType = imageSrcPath = None
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True) 
        return render_template("users/general/search.html", searchInput=searchInput, foundResults=foundResults, foundResultsLen=len(foundResults), imageSrcPath=imageSrcPath, accType = userInfo[1])
    
    return render_template("users/general/search.html", searchInput=searchInput, foundResults=foundResults, foundResultsLen=len(foundResults), accType=accType)

@app.route("/admin-profile", methods=["GET","POST"])
def adminProfile():
    validate_session()
    # for logged users that are not admins
    if ("user" in session):
        return redirect(url_for("userProfile"))

    if ("admin" in session):
        imageSrcPath, userInfo = get_image_path(session["admin"], returnUserInfo=True)
        userID = userInfo[0]
        userUsername = userInfo[1]
        userEmail = userInfo[2]

        return render_template("users/admin/admin_profile.html", imageSrcPath=imageSrcPath, userUsername=userUsername, userEmail=userEmail, userID=userID, accType=userInfo[1])

    # for guests
    return redirect(url_for("login"))

@app.route("/admin-dashboard", methods=["GET","POST"])
def adminDashboard():
    validate_session()
    return "test"

@app.route("/teapot")
def teapot():
    validate_session()
    abort(418)

"""Custom Error Pages"""

# Bad Request
@app.errorhandler(400)
def error400(e):
    validate_session()
    return render_template("errors/401.html"), 400

# Unauthorised
@app.errorhandler(401)
def error401(e):
    validate_session()
    return render_template("errors/401.html"), 401

# Forbidden
@app.errorhandler(403)
def error403(e):
    validate_session()
    return render_template("errors/403.html"), 403

# Not Found
@app.errorhandler(404)
def error404(e):
    validate_session()
    return render_template("errors/404.html"), 404

# Method Not Allowed
@app.errorhandler(405)
def error405(e):
    validate_session()
    return render_template("errors/405.html"), 405

# Payload Too Large
@app.errorhandler(413)
def error413(e):
    validate_session()
    return render_template("errors/413.html"), 413

# I'm a Teapot
@app.errorhandler(418)
def error418(e):
    validate_session()
    return render_template("errors/418.html"), 418

# Too Many Requests
@app.errorhandler(429)
def error429(e):
    validate_session()
    return render_template("errors/429.html"), 429

# Internal Server Error
@app.errorhandler(500)
def error500(e):
    validate_session()
    return render_template("errors/500.html"), 500

# Not Implemented
@app.errorhandler(501)
def error501(e):
    validate_session()
    return render_template("errors/501.html"), 501

# Bad Gateway
@app.errorhandler(502)
def error502(e):
    validate_session()
    return render_template("errors/502.html"), 502

# Service Temporarily Unavailable
@app.errorhandler(503)
def error503(e):
    validate_session()
    return render_template("errors/503.html"), 503

"""End of Custom Error Pages"""

if (__name__ == "__main__"):
    scheduler.configure(timezone="Asia/Singapore") # configure timezone to always follow Singapore's timezone
    scheduler.add_job(lambda: sql_operation(table="session", mode="delete_expired_sessions"), trigger="cron", hour=23, minute=58, second=0, id="deleteExpiredSessions")
    scheduler.add_job(lambda: sql_operation(table="login_attempts", mode="reset_attempts_past_reset_date"), trigger="cron", hour=23, minute=59, second=0, id="resetLockedAccounts")
    scheduler.add_job(lambda: sql_operation(table="user_ip_addresses", mode="remove_last_accessed_more_than_10_days"), trigger="interval", hours=1, id="removeUnusedIPAddresses")
    scheduler.add_job(lambda: splunk_log_retry(), trigger="cron", hour=1, id="splunkLogRetry")
    scheduler.start()
    app.run(debug=app.config["DEBUG_FLAG"], port=environ.get("PORT", 8080))