"""
Routes for error pages
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, abort, url_for, Markup

errorBP = Blueprint("errorBP", __name__, static_folder="static", template_folder="template")

# Bad Request
@errorBP.app_errorhandler(400)
def error400(e):
    return render_template(
        "error_base.html", title="400 Bad Request", errorNo=400,
        description="Your request was a malformed or illegal request."
    ), 400

# Unauthorised
@errorBP.app_errorhandler(401)
def error401(e):
    return render_template(
        "error_base.html", title="401 Unauthorised", errorNo=401,
        description="CourseFinity is unable to authorise your request."
    ), 401

# Payment Required
@errorBP.app_errorhandler(402)
def error402(e):
    return render_template(
        "error_base.html", title="402 Payment Required", errorNo=402,
        description=Markup(
            f"Your request requires payment to be resolved. You will be redirected to the <a href='{url_for('userBP.shoppingCart')}'>shopping cart</a> in 5 seconds."
        ),
        head=(Markup(f"<meta http-equiv='refresh' content='5;url={url_for('userBP.shoppingCart')}'/>"),)
    ), 402

# Forbidden
@errorBP.app_errorhandler(403)
def error403(e):
    return render_template(
        "error_base.html", title="403 Forbidden", errorNo=403,
        description="You do not have permission to access this resource."
    ), 403

# Not Found
@errorBP.app_errorhandler(404)
def error404(e):
    return render_template(
        "error_base.html", title="404 Not Found", errorNo=404,
        description="We're sorry but it looks like that page doesn't exist anymore."
    ), 404

# Method Not Allowed
@errorBP.app_errorhandler(405)
def error405(e):
    return render_template(
        "error_base.html", title="405 Method Not Allowed", errorNo=405,
        description="The page you are looking for cannot be displayed because the requested method is not allowed."
    ), 405

# Payload Too Large
@errorBP.app_errorhandler(413)
def error413(e):
    return render_template(
        "error_base.html", title="413 Payload Too Large", errorNo=413,
        description="Request entity is larger than limits defined by CourseFinity's server."
    ), 413

# I'm a Teapot
@errorBP.route("/teapot")
def teapot():
    abort(418)

@errorBP.app_errorhandler(418)
def error418(e):
    return render_template(
        "error_base.html", title="418 I'm a Teapot", errorNo=418,
        description=Markup("<i class='fas fa-mug-hot'></i><br>The request entity is short and stout.")
    ), 418

# Too Many Requests
@errorBP.app_errorhandler(429)
def error429(e):
    return render_template(
        "error_base.html", title="429 Too Many Requests", errorNo=429,
        description="Sorry! Rate limit exceeded. Please try again later."
    ), 429

# Internal Server Error
@errorBP.app_errorhandler(500)
def error500(e):
    return render_template(
        "error_base.html", title="500 Internal Server Error", errorNo=500,
        description="The server encountered an internal error or misconfiguration and was unable to complete your request."
    ), 500

# Not Implemented
@errorBP.app_errorhandler(501)
def error501(e):
    return render_template(
        "error_base.html", title="501 Not Implemented", errorNo=501,
        description="The server is unable to process your request."
    ), 501

# Bad Gateway
@errorBP.app_errorhandler(502)
def error502(e):
    return render_template(
        "error_base.html", title="502 Bad Gateway", errorNo=502,
        description="The server encountered a temporary error and was unable to complete your request. Please try again later."
    ), 502

# Service Temporarily Unavailable
@errorBP.app_errorhandler(503)
def error503(e):
    return render_template(
        "error_base.html", title="503 Service Temporarily Unavailable", errorNo=503,
        description="This could be due to maintenance downtime or capacity problems. Please try again later."
    ), 503