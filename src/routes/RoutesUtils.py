# import flask libraries (Third-party libraries)
from flask import render_template, request, session, abort, current_app, redirect, wrappers, url_for
from flask_limiter.util import get_remote_address
from jsonschema import validate

# import local python libraries
from python_files.functions.SQLFunctions import sql_operation
from python_files.functions.NormalFunctions import upload_new_secret_version, generate_secure_random_bytes
from python_files.classes.Roles import RoleInfo

# import python standard libraries
import json

schema = {
    
}

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
    if (current_app.config["MAINTENANCE_MODE"] and request.endpoint != "static"):
        return render_template("maintenance.html", estimation="soon!")

    # RBAC Check if the user is allowed to access the pages that they are allowed to access
    if (request.endpoint is None):
        print("Route Error: Either Does Not Exist or Cannot Access")
        abort(404)

    # check if 2fa_token key is in session
    # remove if the user is no longer on the setup 2FA page anymore
    if ("2fa_token" in session):
        if (request.endpoint and request.endpoint != "static" and request.endpoint.split(".")[-1] != "twoFactorAuthSetup"):
            session.pop("2fa_token", None)

    # check if relative_url key is in session
    # Remove if the admin is not on the userManagement page anymore
    if ("relative_url" in session):
        if (
            request.endpoint and 
            request.endpoint != "static" and 
            request.endpoint.split(".")[-1] not in ("userManagement", "adminManagement")
        ):
            session.pop("relative_url", None)

    # check if historyCurPage key is in session
    # Remove if the user is not on the any of the purchase history related pages anymore
    if ("historyCurPage" in session):
        if (
            request.endpoint and 
            request.endpoint != "static" and 
            request.endpoint.split(".")[-1] not in ("purchaseHistory", "courseReview", "purchaseView")
        ):
            session.pop("historyCurPage", None)

    # Validate the user's session for every request that is not to the static files
    if (request.endpoint != "static"):
        print(f"Session cookie: {session}")
        if (("user" in session) ^ ("admin" in session)):
            # if either user or admin is in the session cookie value (but not both)
            userID = session.get("user") or session.get("admin")
            sessionID = session.get("sid")

            if (
                sessionID is not None and 
                not sql_operation(
                    table="session",
                    mode="check_if_valid", 
                    sessionID=sessionID, 
                    userID=userID, 
                    userIP=get_remote_address(), 
                    userAgent=request.user_agent.string
                )
            ):
                # if session does not exist in the db or is in invalid
                print("Session cleared due to invalid session ID!")
                session.clear()
            elif (sessionID is None):
                # if session ID is missing from the cookie
                print("Session cleared due to missing session ID!")
                session.clear()

    # If the admin still has the session cookie but is not in a whitelisted IP address
    if ("admin" in session):
        if (not current_app.config["DEBUG_FLAG"]):
            adminWhitelistedIP = json.loads(
                current_app.config["SECRET_CONSTANTS"].get_secret_payload(secretID="ip-address-whitelist")
            )
            # try:
            #     validate(instance=adminWhitelistedIP, schema=schema)
            # except:
            #     print("Error in JSON Schema")
        else:
            adminWhitelistedIP = ["127.0.0.1"]

        if (get_remote_address() not in adminWhitelistedIP):
            session.clear()
            abort(403)

    if ("user" in session and "admin" in session):
        # both user and admin are in session cookie value
        # clear the session as it should not be possible to have both session
        session.clear()

    if (request.endpoint != "static"):
        # Retrieve the roles database, there could be a better way to do this
        roles = sql_operation(table="role", mode="retrieve_all")
        roleTable = {}
        for idx, role in enumerate(roles): # iterate through each role and append the information to a list
            currentRoleName = current_app.config["CONSTANTS"].ROLE_NAME_ORDER_TUPLE[idx]
            roleTable[currentRoleName] = RoleInfo(role).format_blueprints_for_checking()

        requestBlueprint = request.endpoint
        hasBlueprint = False
        if ("." in request.endpoint):
            requestBlueprint = request.endpoint.split(".")[0]
            hasBlueprint = True

        print("Request Endpoint:", request.endpoint)
        if (hasBlueprint):
            print("Request Blueprint:", requestBlueprint)

        allowedAccess = False
        if (not hasBlueprint):
            # Since all routes have a blueprint, 
            # abort(404) if the request does not have a blueprint
            abort(404)
        elif ("user" in session and requestBlueprint in roleTable["Student"]):
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
            #TODO: config the cache control for security purposes
            # cache control shld be private as we dont want our proxy to cache the response
            # Disable caching for state changing requests (if NOT in debug/dev mode)
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response