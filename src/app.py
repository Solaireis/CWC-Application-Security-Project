# import third party libraries
from apscheduler.schedulers.background import BackgroundScheduler

# import flask libraries (Third-party libraries)
from flask import Flask, render_template, request, session, abort
from flask import wrappers
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf

# import local python libraries
from python_files.functions.SQLFunctions import sql_operation, get_image_path
from python_files.functions.NormalFunctions import get_IP_address_blacklist, upload_new_secret_version
from python_files.classes.Constants import CONSTANTS

# import python standard libraries
from secrets import token_bytes
from pathlib import Path
from os import environ
from datetime import timedelta

"""------------------------------------- START OF WEB APP CONFIGS -------------------------------------"""

# general Flask configurations
app = Flask(__name__)

# flask extension that prevents cross site request forgery
app.config["CSRF_COOKIE_SECURE"] = True
app.config["CSRF_COOKIE_HTTPONLY"] = True
app.config["CSRF_COOKIE_TIMEOUT"] = timedelta(days=1)
csrf = SeaSurf(app)

# flask extension that helps set policies for the web app
csp = {
    'script-src':[
        '\'self\'',
        'https://code.jquery.com/jquery-3.6.0.min.js',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
        'https://cdn.jsdelivr.net/npm/less@4',
        'https://www.google.com/recaptcha/enterprise.js',
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
def update_secret_key() -> None:
    """
    Update Flask's secret key for the web app session cookie by generating a new one
    and uploading it to Google Secret Manager API.

    Used for setting and rotating the secret key for the session cookie.
    """
    # Check if the web application is already in maintenance mode
    isInMaintenanceMode = app.config["MAINTENANCE_MODE"]
    if (not isInMaintenanceMode):
        app.config["MAINTENANCE_MODE"] = True

    # Generate a new key using the secrets module from Python standard library
    # as recommended by OWASP to ensure higher entropy: 
    # https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation
    app.config["SECRET_KEY"] = token_bytes(CONSTANTS.SESSION_NUM_OF_BYTES)
    upload_new_secret_version(
        secretID=CONSTANTS.FLASK_SECRET_KEY_NAME,
        secret=app.config["SECRET_KEY"],
        destroyPastVer=True,
        destroyOptimise=True
    )

    # if the web application is already in maintenance mode, don't set it to false to avoid potential issues
    if (not isInMaintenanceMode):
        app.config["MAINTENANCE_MODE"] = False

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
app.config["SESSION_COOKIE_SECURE"] = True

# for other scheduled tasks such as deleting expired session id from the database
scheduler = BackgroundScheduler()

# Remove jinja whitespace
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Maximum file size for uploading anything to the web app's server
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024 # 200MiB

# for image uploads file path
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ("png", "jpg", "jpeg")

# for course video uploads file path
app.config["COURSE_VIDEO_FOLDER"] = Path(app.root_path).joinpath("static", "course_videos")
app.config["ALLOWED_VIDEO_EXTENSIONS"] = (".mp4, .mov, .avi, .3gpp, .flv, .mpeg4, .flv, .webm, .mpegs, .wmv")

# add the constant object to the flask app
app.config["CONSTANTS"] = CONSTANTS

# rate limiter configuration using flask limiter
with app.app_context():
    from routes.RoutesLimiter import limiter
    limiter.init_app(app)

# Register all app routes
from routes.SuperAdmin import superAdminBP
app.register_blueprint(superAdminBP)

from routes.Admin import adminBP
app.register_blueprint(adminBP)

from routes.Errors import errorBP
app.register_blueprint(errorBP)

from routes.General import generalBP
app.register_blueprint(generalBP)

with app.app_context():
    from routes.Guest import guestBP
    app.register_blueprint(guestBP)

from routes.LoggedIn import loggedInBP
app.register_blueprint(loggedInBP)

from routes.User import userBP
app.register_blueprint(userBP)

from routes.Teacher import teacherBP
app.register_blueprint(teacherBP)

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

    # RBAC Check if the user is allowed to access the pages that they are allowed to access
    if (request.endpoint is None):
        print("Route Error: Either Does Not Exist or Cannot Access")
        abort(404)

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

    if (request.endpoint != "static"):
        requestBlueprint = request.endpoint.split(".")[0] if ("." in request.endpoint) else request.endpoint
        print("Request Endpoint:", request.endpoint)
        if ("user" in session and requestBlueprint in CONSTANTS.USER_BLUEPRINTS):
            pass # allow the user to access the page

        elif("user" in session and requestBlueprint in CONSTANTS.TEACHER_BLUEPRINTS):
            imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
            if userInfo[1] != "Teacher":
                return abort(404) #allow the teacher to access the page
            pass

        elif("admin" in session and requestBlueprint in CONSTANTS.ADMIN_BLUEPRINTS):
            pass #allow the admin to access the page

        elif ("user" not in session and "admin" not in session and "teacher" not in session and requestBlueprint in CONSTANTS.GUEST_BLUEPRINTS):
            pass # allow the guest user to access the page

        else:
            # If the user is not allowed to access the page, abort 404
            return abort(404)

    # Validate the user's session for every request that is not to the static files
    if (request.endpoint != "static"):
        if (("user" in session) ^ ("admin" in session)):
            # if either user or admin is in the session cookie value (but not both)
            userID = session.get("user") or session.get("admin")
            sessionID = session["sid"]

            if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
                # if user session is invalid as the user does not exist anymore
                sql_operation(table="session", mode="delete_session", sessionID=sessionID)
                session.clear()
                return

            if (sql_operation(table="session", mode="if_session_exists", sessionID=sessionID)):
                # if session exists
                if (not sql_operation(table="session", mode="check_if_valid", sessionID=sessionID, userID=userID, userIP=get_remote_address(), userAgent=request.user_agent.string)):
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
    Add headers to the response after each request.
    """
    # it is commented out as we are still developing the web app and it is not yet ready to be hosted.
    # will be uncommented when the web app is ready to be hosted on firebase.
    if (request.endpoint != "static"):
        response.headers["Cache-Control"] = "public, max-age=0"
    elif (not CONSTANTS.DEBUG_MODE):
        # Cache for 1 year for static files (except when in debug/dev mode)
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response

if (__name__ == "__main__"):
    scheduler.configure(timezone="Asia/Singapore") # configure timezone to always follow Singapore's timezone

    # APScheduler docs:
    # https://apscheduler.readthedocs.io/en/latest/modules/triggers/cron.html
    # Free up database of users who have not verified their email for more than 30 days
    scheduler.add_job(
        lambda: sql_operation(table="user", mode="remove_unverified_users_more_than_30_days"),
        trigger="cron", hour=23, minute=56, second=0, id="removeUnverifiedUsers"
    )
    # Free up the database of expired JWT
    scheduler.add_job(
        lambda: sql_operation(table="limited_use_jwt", mode="delete_expired_jwt"),
        trigger="cron", hour=23, minute=57, second=0, id="deleteExpiredJWT"
    )
    # Free up the database of expired sessions
    scheduler.add_job(
        lambda: sql_operation(table="session", mode="delete_expired_sessions"), 
        trigger="cron", hour=23, minute=58, second=0, id="deleteExpiredSessions"
    )
    # Free up database of expired login attempts
    scheduler.add_job(
        lambda: sql_operation(table="login_attempts", mode="reset_attempts_past_reset_date"), 
        trigger="cron", hour=23, minute=59, second=0, id="resetLockedAccounts"
    )
    # Remove user's IP address from the database if the the user has not logged in from that IP address for more than 10 days
    scheduler.add_job(
        lambda: sql_operation(table="user_ip_addresses", mode="remove_last_accessed_more_than_10_days"),
        trigger="interval", hours=1, id="removeUnusedIPAddresses"
    )
    # Re-encrypt all the encrypted data in the database due to the monthly key rotations
    scheduler.add_job(
        lambda: sql_operation(table="user", mode="re-encrypt_data_in_database"),
        trigger="cron", day="last", hour=3, minute=0, second=0, id="reEncryptDataInDatabase"
    )
    # For key rotation of the secret key for digitally signing the session cookie
    scheduler.add_job(
        update_secret_key,
        trigger="cron", day="last", hour=23, minute=59, second=59, id="updateFlaskSecretKey"
    )
    scheduler.start()

    SSL_CONTEXT = (
        CONSTANTS.CONFIG_FOLDER_PATH.joinpath("flask-cert.pem"), 
        CONSTANTS.CONFIG_FOLDER_PATH.joinpath("flask-private-key.pem")
    )
    app.run(debug=app.config["DEBUG_FLAG"], port=environ.get("PORT", 8080), ssl_context=SSL_CONTEXT)