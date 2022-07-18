# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, current_app, redirect
from flask import wrappers
from flask_limiter.util import get_remote_address

# import local python libraries
from python_files.functions.SQLFunctions import sql_operation
from python_files.functions.NormalFunctions import get_IP_address_blacklist, upload_new_secret_version, generate_secure_random_bytes

# import python standard libraries
import re

def update_secret_key() -> None:
    """
    Update Flask's secret key for the web app session cookie by generating a new one
    and uploading it to Google Secret Manager API.

    Used for setting and rotating the secret key for the session cookie.
    """
    # Generate a new key using the secrets module from Python standard library
    # as recommended by OWASP to ensure higher entropy: 
    # https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation
    current_app.config["SECRET_KEY"] = generate_secure_random_bytes(
        nBytes=current_app.config["CONSTANTS"].SESSION_NUM_OF_BYTES, generateFromHSM=True
    )
    upload_new_secret_version(
        secretID=current_app.config["CONSTANTS"].FLASK_SECRET_KEY_NAME,
        secret=current_app.config["SECRET_KEY"],
        destroyPastVer=True,
        destroyOptimise=True
    )

@current_app.before_first_request
def before_first_request() -> None:
    """
    Called called at the very first request to the web app.

    Returns:
    - None
    """
    # get ip address blacklist from a github repo or the saved file
    current_app.config["IP_ADDRESS_BLACKLIST"] = get_IP_address_blacklist()

@current_app.before_request
def before_request() -> None:
    """
    Called before each request to the web app.
    Returns:
    - None
    """
    if (get_remote_address() in current_app.config["IP_ADDRESS_BLACKLIST"]):
        abort(403)

    # Redirect user to coursefinity.social domain if they are not on it
    # Reason: Firebase have their own set of default domain names (that cannot be disabled) 
    # which are not protected by Cloudflare.
    if (re.fullmatch(current_app.config["CONSTANTS"].FIREBASE_DOMAIN_REGEX, request.url) is not None):
        return redirect(
            re.sub(
                current_app.config["CONSTANTS"].FIREBASE_DOMAIN_REGEX, 
                r"https://coursefinity.social\2", 
                request.url
            )
        )

    # RBAC Check if the user is allowed to access the pages that they are allowed to access
    if (request.endpoint is None):
        print("Route Error: Either Does Not Exist or Cannot Access")
        abort(404)

    if (current_app.config["MAINTENANCE_MODE"] and request.endpoint != "static"):
        return render_template("maintenance.html", estimation="soon!")

    # check if 2fa_token key is in session
    # remove if the user is no longer on the setup 2FA page anymore
    if ("2fa_token" in session):
        # remove if the endpoint is not the same as twoFactorAuthSetup
        # note that since before_request checks for every request,
        # meaning the css, js, and images are also checked when a user request the webpage
        # which will cause the 2fa_token key to be removed from the session as the endpoint is "static"
        # hence, adding allowing if the request endpoint is pointing to a static file
        if (request.endpoint and request.endpoint != "static" and request.endpoint.split(".")[-1] != "twoFactorAuthSetup"):
            session.pop("2fa_token", None)

    # check if relative_url key is in session
    # Remove if the admin is not on the userManagement page anymore
    if ("relative_url" in session):
        # remove if the endpoint is not the same as userManagement
        # note that since before_request checks for every request,
        # meaning the css, js, and images are also checked when a user request the webpage
        # which will cause the relative_url key to be removed from the session as the endpoint is "static"
        # hence, adding allowing if the request endpoint is pointing to a static file
        if (request.endpoint and request.endpoint != "static" and request.endpoint.split(".")[-1] != "userManagement"):
            session.pop("relative_url", None)

    # Validate the user's session for every request that is not to the static files
    if (request.endpoint != "static"):
        if (("user" in session) ^ ("admin" in session)):
            # if either user or admin is in the session cookie value (but not both)
            userID = session.get("user") or session.get("admin")
            sessionID = session["sid"]

            if (not sql_operation(table="user", mode="verify_userID_existence", userID=userID)):
                # if user session is invalid as the user does not exist anymore
                sql_operation(table="session", mode="delete_session", sessionID=sessionID)
                print("Session cleared due to invalid user session")
                session.clear()

            elif (sql_operation(table="session", mode="if_session_exists", sessionID=sessionID)):
                # if session exists
                if (not sql_operation(table="session", mode="check_if_valid", sessionID=sessionID, userID=userID, userIP=get_remote_address(), userAgent=request.user_agent.string)):
                    # if user session is expired or the userID does not match with the sessionID
                    sql_operation(table="session", mode="delete_session", sessionID=sessionID)
                    print("Session cleared due to expired session!")
                    session.clear()
                else:
                    # update session expiry time
                    print("Session expiry time updated!")
                    sql_operation(table="session", mode="update_session", sessionID=sessionID)
            else:
                # if session does not exist in the db
                print("Session cleared due to invalid session ID!")
                session.clear()

    # If the admin still has the session cookie but is not in a whitelisted IP address
    if ("admin" in session and not sql_operation(table="whitelisted_ip_addresses", mode="check_if_whitelisted", ipAddress=get_remote_address())):
        session.clear()
        abort(403)

    if ("user" in session and "admin" in session):
        # both user and admin are in session cookie value
        # clear the session as it should not be possible to have both session
        session.clear()

    if (request.endpoint != "static"):
        requestBlueprint = request.endpoint.split(".")[0] if ("." in request.endpoint) else request.endpoint
        print("Request Endpoint:", request.endpoint)
        if ("user" in session and requestBlueprint in current_app.config["CONSTANTS"].USER_BLUEPRINTS):
            pass # allow the user to access the page

        elif("user" in session and requestBlueprint in current_app.config["CONSTANTS"].TEACHER_BLUEPRINTS):
            userInfo = sql_operation(table="user", mode="get_user_data", userID=session["user"])
            if (userInfo.role != "Teacher"):
                return abort(404) # allow the teacher to access the page
            pass

        elif ("admin" in session):
            isSuperAdmin = sql_operation(table="user", mode="check_if_superadmin", userID=session["admin"])
            if (not isSuperAdmin and requestBlueprint in current_app.config["CONSTANTS"].ADMIN_BLUEPRINTS):
                pass # allow the admin to access the page
            elif (isSuperAdmin and requestBlueprint in current_app.config["CONSTANTS"].SUPER_ADMIN_BLUEPRINTS):
                pass # allow the superadmin to access the page
            else:
                # if the admin is not allowed to access the page, abort 404
                return abort(404)

        elif ("user" not in session and "admin" not in session and "teacher" not in session and requestBlueprint in current_app.config["CONSTANTS"].GUEST_BLUEPRINTS):
            pass # allow the guest user to access the page

        else:
            # If the user is not allowed to access the page, abort 404
            return abort(404)

@current_app.after_request # called after each request to the application
def after_request(response:wrappers.Response) -> wrappers.Response:
    """
    Add headers to the response after each request.
    """
    # it is commented out as we are still developing the web app and it is not yet ready to be hosted.
    # will be uncommented when the web app is ready to be hosted on firebase.
    if (request.endpoint != "static"):
        response.headers["Cache-Control"] = "public, max-age=0"
    elif (not current_app.config["CONSTANTS"].DEBUG_MODE):
        # Cache for 1 year for static files (except when in debug/dev mode)
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response