# import third-party libraries
from apscheduler.schedulers.background import BackgroundScheduler

# import flask libraries (Third-party libraries)
from flask import Flask
from flask.sessions import SecureCookieSessionInterface
from flask_talisman import Talisman

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import local python libraries
from python_files.classes.Constants import SECRET_CONSTANTS, CONSTANTS
from python_files.classes.Course import get_readable_category
from python_files.functions.SQLFunctions import sql_operation

# import python standard libraries
from pathlib import Path
from os import environ
from datetime import timedelta
import logging, hashlib

"""------------------------------------- START OF WEB APP CONFIGS -------------------------------------"""

app = Flask(__name__)

# Add the constants objects to the Flask web app
app.config["CONSTANTS"] = CONSTANTS
app.config["SECRET_CONSTANTS"] = SECRET_CONSTANTS

# Flask session cookie configurations
# Configure the default FLask session default
# salt and HMAC algorithm to something more secure
# Source Codes Reference: 
#   - Salt:
#       - https://github.com/pallets/flask/blob/main/src/flask/sessions.py#L333
#   - HMAC-SHA1:
#       - https://github.com/pallets/flask/blob/96726f6a04251bde39ec802080c9008060e0b5b9/src/flask/sessions.py#L316
#       - https://github.com/pallets/itsdangerous/blob/484d5e6d3c613160cb6c9336b9454f3204702e74/src/itsdangerous/signer.py#L67
FLASK_SESSION_COOKIE_INTERFACE = SecureCookieSessionInterface()
FLASK_SESSION_COOKIE_INTERFACE.salt = app.config["SECRET_CONSTANTS"].get_secret_payload(
    secretID=app.config["CONSTANTS"].FLASK_SALT_KEY_NAME, decodeSecret=False
)
FLASK_SESSION_COOKIE_INTERFACE.digest_method = staticmethod(hashlib.sha512)
app.session_interface = FLASK_SESSION_COOKIE_INTERFACE

# Secret key mainly for digitally signing the session cookie
# it will retrieve the secret key from Google Secret Manager API
app.config["SECRET_KEY"] = app.config["SECRET_CONSTANTS"].get_secret_payload(
    secretID=app.config["CONSTANTS"].FLASK_SECRET_KEY_NAME, decodeSecret=False
)

# Import security related functions/objects
with (app.app_context()):
    from routes.RoutesSecurity import csrf, limiter

# Rate limiter configuration using flask limiter
limiter.init_app(app)

# Integrate Google CLoud Logging to the Flask app
gcp_logging.handlers.setup_logging(app.config["SECRET_CONSTANTS"].GOOGLE_LOGGING_HANDLER)
logging.getLogger().setLevel(logging.INFO)
app.logger.addHandler(app.config["SECRET_CONSTANTS"].GOOGLE_LOGGING_HANDLER)

# Add gunicorn logger to the Flask app (when in production)
if (not app.config["CONSTANTS"].DEBUG_MODE):
    gunicornLogger = logging.getLogger("gunicorn.error")
    app.logger.addHandler(gunicornLogger)

# Flask SeaSurf to prevents cross-site request forgery
app.config["CSRF_COOKIE_NAME"] = "csrf_token"
app.config["CSRF_COOKIE_SECURE"] = True
app.config["CSRF_COOKIE_HTTPONLY"] = True
app.config["CSRF_COOKIE_SAMESITE"] = "Lax"
app.config["CSRF_COOKIE_TIMEOUT"] = timedelta(days=1)
csrf.init_app(app)

# Flask Talisman to helps set policies
# and security related configurations for the web application
CSP = {
    "style-src": [
        "'self'",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css",
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css",
        # "https://cdnjs.cloudflare.com/ajax/libs/video.js/7.19.2/video-js.min.css",
        # "https://cdnjs.cloudflare.com/ajax/libs/video.js/7.19.2/video.min.js \'unsafe-inline\'",
        # "https://unpkg.com/@videojs/themes@1/dist/forest/index.css",
        "https://vjs.zencdn.net/7.19.2/video-js.css",
        "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css",
        "https://unpkg.com/dropzone@5/dist/min/dropzone.min.css",
    ],
    "frame-src":[
        "'self'",
        "https://www.google.com/recaptcha/",
        "https://player.vdocipher.com/v2/",
    ],
    "script-src":[
        "'self'",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js",
        "https://cdn.jsdelivr.net/npm/less@4",
        "https://www.google.com/recaptcha/enterprise.js",
        "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js",
        "https://player.vdocipher.com/v2/api.js",
        # "https://cdnjs.cloudflare.com/ajax/libs/video.js/7.19.2/video.min.js blob:",
        # "https://cdn.dashjs.org/v4.4.0/dash.all.min.js",
        # "https://cdn.jsdelivr.net/npm/videojs-contrib-dash@5.1.1/dist/videojs-dash.cjs.min.js",
        "https://unpkg.com/dropzone@5/dist/min/dropzone.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js",
    ]
}
PERMS_POLICY = {
    "geolocation": "()",
    "microphone": "()"
}
talisman = Talisman(
    app=app,

    # The web application's policies
    permissions_policy=PERMS_POLICY,

    # CSP configurations
    content_security_policy=CSP,
    content_security_policy_nonce_in=["script-src"],

    # XSS protection configuration
    # to prevent reflected XSS attacks
    x_xss_protection=True, # Will require nonce="{{ csp_nonce() }}" in script tags

    # HTTPS configurations to redirect
    # HTTP requests to use HTTPS
    # Note: This is still vulnerable to MITM attacks
    force_https=True, # Note: Will be disabled in debug mode
    force_https_permanent=True,

    # HSTS configurations to tell the browser
    # to automatically use HTTPS for the next 1 year
    # to prevents MITM attacks.
    # Note: HSTS is also enabled on our custom domain via Cloudflare
    strict_transport_security=True,
    strict_transport_security_preload=True,
    strict_transport_security_max_age=31536000, # 1 year
    strict_transport_security_include_subdomains=True,

    # Flask session cookie configurations
    session_cookie_secure=True, # Note: Will be disabled in debug mode
    session_cookie_http_only=True,
    session_cookie_samesite="Lax"
)

# Additional Flask session cookie configurations
app.config["SESSION_PERMANENT"] = False # Session cookie will be deleted when the browser is closed
# Since secure cookie is disabled in debug mode by Flask-Talisman,
if (app.config["CONSTANTS"].DEBUG_MODE):
    # Override the session cookie secure configuration
    # if in debug mode to enable secure cookie
    app.config["SESSION_COOKIE_SECURE"] = True 

# Debug flag (will be set to false when deployed)
app.config["DEBUG_FLAG"] = app.config["CONSTANTS"].DEBUG_MODE

# Maintenance mode flag
app.config["MAINTENANCE_MODE"] = False

# Remove Jinja2 whitespace
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Add custom functions to Jinja2
app.jinja_env.globals.update(get_readable_category=get_readable_category)

# Maximum file size for uploading anything to the web app's server
app.config["MAX_CONTENT_LENGTH"] = 75 * 1024 * 1024 # 75MiB

# for image uploads file path
app.config["ALLOWED_IMAGE_EXTENSIONS"] = app.config["CONSTANTS"].ALLOWED_IMAGE_EXTENSIONS

# for course video uploads file path
app.config["USER_IMAGE_FOLDER"] = Path(app.root_path).joinpath("static", "user_profiles")
app.config["COURSE_VIDEO_FOLDER"] = Path(app.root_path).joinpath("static", "course_videos")
app.config["ALLOWED_VIDEO_EXTENSIONS"] = app.config["CONSTANTS"].ALLOWED_VIDEO_EXTENSIONS

# import utility functions into the flask app and get neccessary functions
# such as update_secret_key() for rotation of the secret key
with app.app_context():
    from routes.RoutesUtils import update_secret_key

    # Register all app routes
    from routes.SuperAdmin import superAdminBP
    app.register_blueprint(superAdminBP)

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

    from routes.Teacher import teacherBP
    app.register_blueprint(teacherBP)

    from routes.Files import filesBP
    app.register_blueprint(filesBP)

"""------------------------------------- END OF WEB APP CONFIGS -------------------------------------"""

"""------------------------------------- START OF WEB APP SCHEDULED JOBS -------------------------------------"""

# Note: Not using lambdas for the jobs as on Google Cloud Logging,
# it is hard to tell what jobs have been executed
# E.g. Running job "<lambda> (trigger: cron[hour='23', minute='57', second='0'],
# next run at: 2022-07-11 23:57:00 +08)" (scheduled at 2022-07-10 23:57:00+08:00)

def remove_unverified_users_for_more_than_30_days() -> None:
    """
    Remove unverified users from the database

    >>> sql_operation(table="user", mode="remove_unverified_users_more_than_30_days")
    """
    sql_operation(table="user", mode="remove_unverified_users_more_than_30_days")

def remove_expired_jwt() -> None:
    """
    Remove expired jwt from the database

    >>> sql_operation(table="limited_use_jwt", mode="delete_expired_jwt")
    """
    sql_operation(table="limited_use_jwt", mode="delete_expired_jwt")

def remove_expired_sessions() -> None:
    """
    Remove expired sessions from the database

    >>> sql_operation(table="session", mode="delete_expired_sessions")
    """
    sql_operation(table="session", mode="delete_expired_sessions")

def reset_expired_login_attempts() -> None:
    """
    Reset expired login attempts for users

    >>> sql_operation(table="login_attempts", mode="reset_attempts_past_reset_date")
    """
    sql_operation(table="login_attempts", mode="reset_attempts_past_reset_date")

def remove_last_accessed_more_than_10_days() -> None:
    """
    Remove last accessed more than 10 days from the database

    >>> sql_operation(table="user_ip_addresses", mode="remove_last_accessed_more_than_10_days")
    """
    sql_operation(table="user_ip_addresses", mode="remove_last_accessed_more_than_10_days")

def re_encrypt_data_in_db() -> None:
    """
    Re-encrypt data in the database

    >>> sql_operation(table="user", mode="re-encrypt_data_in_database")
    """
    sql_operation(table="user", mode="re-encrypt_data_in_database")

def check_for_new_session_configs() -> None:
    """
    Check for any value updates in Google Cloud Platform Secret Manager API
    if the Flask secret key or the session cookie salt has changed.

    If there are changes, update the Flask session cookie configurations.
    """
    retrievedKey = app.config["SECRET_CONSTANTS"].get_secret_payload(
        secretID=app.config["CONSTANTS"].FLASK_SECRET_KEY_NAME, decodeSecret=False
    )
    if (retrievedKey != app.config["SECRET_KEY"]):
        app.config["SECRET_KEY"] = retrievedKey

    retrievedSessionSalt = app.config["SECRET_CONSTANTS"].get_secret_payload(
        secretID=app.config["CONSTANTS"].FLASK_SALT_KEY_NAME, decodeSecret=False
    )
    if (retrievedSessionSalt != app.session_interface.salt):
        app.session_interface.salt = retrievedSessionSalt

"""------------------------------------- END OF WEB APP SCHEDULED JOBS -------------------------------------"""

if (__name__ == "__main__"):
    # APScheduler docs:
    # https://apscheduler.readthedocs.io/en/latest/modules/triggers/cron.html
    scheduler = BackgroundScheduler() # Uses threading to run the task in a separate thread
    scheduler.configure(timezone="Asia/Singapore") # configure timezone to always follow Singapore's timezone

    # Free up database of users who have not verified their email for more than 30 days
    scheduler.add_job(
        remove_unverified_users_for_more_than_30_days,
        trigger="cron", hour=23, minute=56, second=0, id="removeUnverifiedUsers"
    )
    # Free up the database of expired JWT
    scheduler.add_job(
        remove_expired_jwt,
        trigger="cron", hour=23, minute=57, second=0, id="deleteExpiredJWT"
    )
    # Free up the database of expired sessions
    scheduler.add_job(
        remove_expired_sessions,
        trigger="cron", hour=23, minute=58, second=0, id="deleteExpiredSessions"
    )
    # Free up database of expired login attempts
    scheduler.add_job(
        reset_expired_login_attempts,
        trigger="cron", hour=23, minute=59, second=0, id="resetLockedAccounts"
    )
    # Remove user's IP address from the database if the the user has not logged in from that IP address for more than 10 days
    scheduler.add_job(
        remove_last_accessed_more_than_10_days,
        trigger="interval", hours=1, id="removeUnusedIPAddresses"
    )
    # Re-encrypt all the encrypted data in the database due to the monthly key rotations
    scheduler.add_job(
        re_encrypt_data_in_db,
        trigger="cron", day="last", hour=3, minute=0, second=0, id="reEncryptDataInDatabase"
    )
    # For key rotation of the secret key for digitally signing the session cookie
    scheduler.add_job(
        update_secret_key,
        trigger="cron", day="last", hour=23, minute=59, second=59, id="updateFlaskSecretKey"
    )
    # For checking if the Flask secret key has been manually changed every 30 minutes
    scheduler.add_job(
        check_for_new_session_configs,
        trigger="interval", minutes=30, id="checkForNewSessionConfigs"
    )
    # Start all the scheduled jobs
    scheduler.start()

    SSL_CONTEXT = (
        CONSTANTS.CONFIG_FOLDER_PATH.joinpath("flask-cert.pem"),
        CONSTANTS.CONFIG_FOLDER_PATH.joinpath("flask-private-key.pem")
    )

    app.run(debug=app.config["DEBUG_FLAG"], port=int(environ.get("PORT", 8080)), ssl_context=SSL_CONTEXT)