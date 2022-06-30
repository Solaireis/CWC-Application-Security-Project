# import third party libraries
from apscheduler.schedulers.background import BackgroundScheduler

# import flask libraries (Third-party libraries)
from flask import Flask, render_template, request, session, abort
from flask import wrappers
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf

# import local python libraries
from python_files.SQLFunctions import *
from python_files.NormalFunctions import *
from routes.Limiter import limiter

# import python standard libraries
from pathlib import Path
from os import environ

"""------------------------------------- START OF WEB APP CONFIGS -------------------------------------"""

# general Flask configurations
app = Flask(__name__)


# flask extension that prevents cross site request forgery
csrf = SeaSurf(app)

# flask extension that helps set policies for the web app
# temporary, * wildcard allows all
csp = {
    'script-src':[
        '\'self\'',
        'https://code.jquery.com/jquery-3.6.0.min.js',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
        'https://cdn.jsdelivr.net/npm/less@4',
        # 'https://www.google.com/recaptcha/enterprise.js', Don't need
        'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js',
        
    ]
}

permissions_policy = {
    "geolocation": "()",
    "microphone": "()"
}

# nonce="{{ csp_nonce() }}"
# xss_protection is already defaulted True
talisman = Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['script-src'], permissions_policy=permissions_policy, x_xss_protection=True)

# Debug flag (will be set to false when deployed)
app.config["DEBUG_FLAG"] = CONSTANTS.DEBUG_MODE

# Maintenance mode flag
app.config["MAINTENANCE_MODE"] = False

# Session cookie configurations
# More details: https://flask.palletsprojects.com/en/2.1.x/config/?highlight=session#SECRET_KEY
# Secret key mainly for digitally signing the session cookie
# it will retrieve the secret key from Google Secret Manager API
app.config["SECRET_KEY"] = CONSTANTS.get_secret_payload(secretID=CONSTANTS.FLASK_SECRET_KEY_NAME, decodeSecret=False)

# Make it such that the session cookie will be deleted when the browser is closed
app.config["SESSION_PERMANENT"] = False

# Browsers will not allow JavaScript access to cookies marked as “HTTP only” for security.
app.config["SESSION_COOKIE_HTTPONLY"] = True

# https://flask.palletsprojects.com/en/2.1.x/security/#security-cookie
# Lax prevents sending cookies with CSRF-prone requests 
# from external sites, such as submitting a form
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# The name of the session cookie
app.config["SESSION_COOKIE_NAME"] = "session"

# Only allow the session cookie to be sent over HTTPS
# Will be enabled when hosted
if (not CONSTANTS.DEBUG_MODE):
    app.config["SESSION_COOKIE_SECURE"] = True

# for other scheduled tasks such as deleting expired session id from the database
scheduler = BackgroundScheduler()

# rate limiter configuration using flask limiter
limiter.init_app(app)

# Maximum file size for uploading anything to the web app's server
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024 # 200MiB

# for image uploads file path
app.config["PROFILE_UPLOAD_PATH"] = Path(app.root_path).joinpath("static", "images", "user")
app.config["THUMBNAIL_UPLOAD_PATH"] = Path(app.root_path).joinpath("static", "images", "courses", "thumbnails")
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ("png", "jpg", "jpeg")

# for course video uploads file path
app.config["COURSE_VIDEO_FOLDER"] = Path(app.root_path).joinpath("static", "course_videos")
app.config["ALLOWED_VIDEO_EXTENSIONS"] = (".mp4, .mov, .avi, .3gpp, .flv, .mpeg4, .flv, .webm, .mpegs, .wmv")

# To allow Google OAuth2.0 to work as it will only work in https if this not set to 1/True
if (app.config["DEBUG_FLAG"]):
    environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Register all app routes
from routes.Admin import adminBP
app.register_blueprint(adminBP)

from routes.Errors import errorBP
app.register_blueprint(errorBP)

from routes.General import generalBP
app.register_blueprint(generalBP)

from routes.Guest import guestBP
app.register_blueprint(guestBP)

from routes.LoggedIn import loggedInBP
app.register_blueprint(loggedInBP)

from routes.User import userBP
app.register_blueprint(userBP)

"""------------------------------------- END OF WEB APP CONFIGS -------------------------------------"""

"""------------------------------------- START OF APP REQUESTS FUNCTIONS -------------------------------------"""

@app.before_first_request
def before_first_request() -> None:
    """
    Called called at the very first request to the web app.
    Returns:
    - None
    """
    # get ip address blacklist from a github repo or the saved file
    app.config["IP_ADDRESS_BLACKLIST"] = get_IP_address_blacklist()

@app.before_request
def before_request() -> None:
    """
    Called before each request to the web app.
    Returns:
    - None
    """
    if (get_remote_address() in app.config["IP_ADDRESS_BLACKLIST"]):
        abort(403)

    if (app.config["MAINTENANCE_MODE"] and request.endpoint != "static"):
        return render_template("maintenance.html", estimation="soon!")

    # check if 2fa_token key is in session
    if ("2fa_token" in session):
        # remove if the endpoint is not the same as twoFactorAuthSetup
        # note that since before_request checks for every request,
        # meaning the css, js, and images are also checked when a user request the webpage
        # which will cause the 2fa_token key to be removed from the session as the endpoint is "static"
        # hence, adding allowing if the request endpoint is pointing to a static file
        if (request.endpoint != "twoFactorAuthSetup" and request.endpoint != "static"):
            session.pop("2fa_token", None)

    # Validate the user's session for every request that is not to the static files
    if (request.endpoint != "static"):
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
                if (not sql_operation(table="session", mode="check_if_valid", sessionID=sessionID, userID=userID, userIP=get_remote_address())):
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

    if ("user" in session and "admin" in session):
        # both user and admin are in session cookie value
        # clear the session as it should not be possible to have both session
        session.clear()
        return

@app.after_request # called after each request to the application
def after_request(response:wrappers.Response) -> wrappers.Response:
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

if (__name__ == "__main__"):
    scheduler.configure(timezone="Asia/Singapore") # configure timezone to always follow Singapore's timezone
    scheduler.add_job(
        lambda: sql_operation(table="one_time_use_jwt", mode="delete_expired_jwt"),
        trigger="cron", hour=23, minute=57, second=0, id="deleteExpiredJWT"
    )
    scheduler.add_job(
        lambda: sql_operation(table="session", mode="delete_expired_sessions"), 
        trigger="cron", hour=23, minute=58, second=0, id="deleteExpiredSessions"
    )
    scheduler.add_job(
        lambda: sql_operation(table="login_attempts", mode="reset_attempts_past_reset_date"), 
        trigger="cron", hour=23, minute=59, second=0, id="resetLockedAccounts"
    )
    scheduler.add_job(
        lambda: sql_operation(table="user_ip_addresses", mode="remove_last_accessed_more_than_10_days"),
        trigger="interval", hours=1, id="removeUnusedIPAddresses"
    )
    scheduler.start()

    host = None if (CONSTANTS.DEBUG_MODE) else "0.0.0.0"
    app.run(debug=app.config["DEBUG_FLAG"], host=host, port=environ.get("PORT", 8080))