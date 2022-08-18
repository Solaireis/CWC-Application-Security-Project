# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, current_app, redirect, wrappers, url_for
from flask_limiter.util import get_remote_address

# import local python libraries
from python_files.functions.SQLFunctions import sql_operation
from python_files.functions.NormalFunctions import upload_new_secret_version, generate_secure_random_bytes
from python_files.classes.Roles import RoleInfo

# import python standard libraries
import json, re

def get_user_ip() -> str:
    """Get the user's IP address"""
    if (current_app.config["CONSTANTS"].DEBUG_MODE):
        return get_remote_address()
    else:
        # Get the user's IP address from the request.
        # For cloudflare proxy, we need to get from the request headers
        # https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/
        return request.headers.get("CF-Connecting-IP") or get_remote_address()

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

@current_app.before_request
def before_request() -> None:
    """
    Called before each request to the web app.
    Returns:
    - None
    """
    isNotStaticEndpoint = (request.endpoint != "static")
    if (current_app.config["MAINTENANCE_MODE"] and isNotStaticEndpoint):
        return render_template("maintenance.html", estimation="soon!")

    if ("user" in session and "admin" in session):
        # both user and admin are in session cookie value
        # clear the session as it should not be possible to have both session
        session.clear()

    # RBAC Check if the user is allowed to access the pages that they are allowed to access
    if (request.endpoint is None):
        abort(404)

    # Check if the route has a blueprint
    hasBlueprint = False
    requestBlueprint = requestRoute = None
    if (isNotStaticEndpoint):
        if (re.fullmatch(current_app.config["CONSTANTS"].BLUEPRINT_ENDPOINT_REGEX, request.endpoint)):
            splittedRequestEndpoint = request.endpoint.split(sep=".", maxsplit=1)
            requestBlueprint = splittedRequestEndpoint[0]
            requestRoute = splittedRequestEndpoint[1]
            hasBlueprint = True

    if (isNotStaticEndpoint and not hasBlueprint):
        # Since all routes except static endpoint have a blueprint,
        # abort(404) if the request does not have a blueprint
        abort(404)

    # check if state key is in session
    # remove if the user is no longer on the google OAuth2 routes
    if ("state" in session):
        if (isNotStaticEndpoint and requestRoute not in ("loginViaGoogle", "loginCallback")):
            session.pop("state", None)

    # check if 2fa_token key is in session
    # remove if the user is no longer on the setup 2FA or the user profile page anymore
    if ("2fa_token" in session):
        if (isNotStaticEndpoint and requestRoute not in ("twoFactorAuthSetup", "userProfile")):
            session.pop("2fa_token", None)

    # check if relative_url key is in session
    # Remove if the admin is not on the account management routes anymore
    if ("relative_url" in session):
        if (isNotStaticEndpoint and requestRoute not in ("userManagement", "adminManagement")):
            session.pop("relative_url", None)

    # check if courseAddedStatus in session
    # Remove if the user did not go to the cart page by intercepting the response
    if ("courseAddedStatus" in session):
        if (isNotStaticEndpoint and requestRoute not in ("addToCart", "shoppingCart")):
            session.pop("courseAddedStatus", None)

    # Remove 2FA session keys if the user is no longer trying to login
    if (
        "ip_details" in session or
        "password_compromised" in session or
        "temp_uid" in session or
        "token" in session or
        "courseAddedStatus" in session
    ):
        if (isNotStaticEndpoint and requestRoute not in ("login", "enter2faTOTP", "enterGuardTOTP")):
            session.pop("ip_details", None)
            session.pop("password_compromised", None)
            session.pop("temp_uid", None)
            session.pop("token", None)
            session.pop("courseAddedStatus", None)

    # check if historyCurPage key is in session
    # Remove if the user is not on the any of the purchase history related pages anymore
    if ("historyCurPage" in session):
        if (isNotStaticEndpoint and requestRoute not in ("purchaseHistory", "courseReview", "purchaseView")):
            session.pop("historyCurPage", None)

    # Validate the user's session for every request that is not to the static files
    if (isNotStaticEndpoint):
        if (("user" in session) ^ ("admin" in session)):
            # if either user or admin is in the session cookie value (but not both)
            userID = session.get("user") or session.get("admin")
            sessionID = session.get("sid")

            if (
                sessionID is not None and
                sql_operation(
                    table="session",
                    mode="check_if_valid",
                    sessionID=sessionID,
                    userID=userID,
                    userIP=get_user_ip(),
                    userAgent=request.user_agent.string
                )
            ):
                # if session ID is valid
                pass
            elif (sessionID is None):
                # if session ID is missing from the cookie
                print("Session cleared due to missing session ID!")
                session.clear()
            else:
                # if session does not exist in the db or is in invalid
                print("Session cleared due to invalid session ID!")
                session.clear()

    # If the admin still has the session cookie but is not in a whitelisted IP address
    if ("admin" in session):
        if (not current_app.config["DEBUG_FLAG"]):
            adminWhitelistedIP = tuple(json.loads(
                current_app.config["SECRET_CONSTANTS"].get_secret_payload(secretID="ip-address-whitelist")
            ))
        else:
            adminWhitelistedIP = ("127.0.0.1",)

        if (get_user_ip() not in adminWhitelistedIP):
            session.clear()
            abort(403)

    if (isNotStaticEndpoint):
        # Retrieve the roles database, there could be a better way to do this
        roles = sql_operation(table="role", mode="retrieve_all")
        roleTable = {}
        for idx, role in enumerate(roles): # iterate through each role and append the information to a list
            currentRoleName = current_app.config["CONSTANTS"].ROLE_NAME_ORDER_TUPLE[idx]
            roleTable[currentRoleName] = RoleInfo(role).format_blueprints_for_checking()

        allowedAccess = False
        if ("user" in session and requestBlueprint in roleTable["Student"]):
            allowedAccess = True # allow the user to access the page
        elif ("user" in session and requestBlueprint in roleTable["Teacher"]):
            if (session.get("isTeacher", False)):
                allowedAccess = True # allow the teacher to access the page
        elif ("admin" in session):
            isSuperAdmin = session.get("isSuperAdmin", False)
            if (not isSuperAdmin and requestBlueprint in roleTable["Admin"]):
                allowedAccess = True # allow the admin to access the page
            elif (isSuperAdmin and requestBlueprint in roleTable["SuperAdmin"]):
                allowedAccess = True # allow the superadmin to access the page
        elif ("user" not in session and "admin" not in session and requestBlueprint in roleTable["Guest"]):
            allowedAccess = True # allow the guest user to access the page

        if (not allowedAccess):
            blueprintRedirectTable = {}
            if ("user" in session):
                if (session.get("isTeacher", False)):
                    # If the teacher user is not allowed to access the page
                    blueprintRedirectTable = current_app.config["CONSTANTS"].TEACHER_REDIRECT_TABLE
                else: # If the student user is not allowed to access the page
                    blueprintRedirectTable = current_app.config["CONSTANTS"].USER_REDIRECT_TABLE
            elif ("admin" in session):
                if (session.get("isSuperAdmin", False)):
                    # If the super-admin user is not allowed to access the page
                    blueprintRedirectTable = current_app.config["CONSTANTS"].SUPERADMIN_REDIRECT_TABLE
                else: # If the admin user is not allowed to access the page
                    blueprintRedirectTable = current_app.config["CONSTANTS"].ADMIN_REDIRECT_TABLE
            else:
                # If the guest user is not allowed to access the page
                blueprintRedirectTable = current_app.config["CONSTANTS"].GUEST_REDIRECT_TABLE

            if (request.endpoint in blueprintRedirectTable):
                return redirect(url_for(blueprintRedirectTable[request.endpoint], **request.view_args))
            elif (requestBlueprint in blueprintRedirectTable):
                return redirect(url_for(blueprintRedirectTable[requestBlueprint], **request.view_args))
            else:
                abort(404)

@current_app.after_request # called after each request to the application
def after_request(response:wrappers.Response) -> wrappers.Response:
    """
    Add headers to the response after each request.
    """
    if (not current_app.config["CONSTANTS"].DEBUG_MODE):
        if (request.endpoint == "static"):
            # Cache for 1 year for static files (except when in debug/dev mode)
            response.headers["Cache-Control"] = "public, max-age=31536000"
        else:
            # cache control shld be private as we dont want our proxy to cache the response
            # Disable caching for state changing requests (if NOT in debug/dev mode)
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response
