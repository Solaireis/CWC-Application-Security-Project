"""
Routes for error pages
"""
# import flask libraries (Third-party libraries)
from flask import Blueprint, render_template, abort
from werkzeug.exceptions import HTTPException, default_exceptions, _aborter

# Error 402 is currently experimental. 
# More info here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/402
class PaymentRequired(HTTPException):
    code = 402
    description = '<p>Payment required.</p>'

default_exceptions[402] = PaymentRequired
_aborter.mapping[402] = PaymentRequired

errorBP = Blueprint("errorBP", __name__, static_folder="static", template_folder="template")

# Bad Request
@errorBP.app_errorhandler(400)
def error400(e):
    return render_template("errors/401.html"), 400

# Unauthorised
@errorBP.app_errorhandler(401)
def error401(e):
    return render_template("errors/401.html"), 401

# Payment Required
@errorBP.app_errorhandler(402)
def error402(e):
    return render_template("errors/402.html"), 402

# Forbidden
@errorBP.app_errorhandler(403)
def error403(e):
    return render_template("errors/403.html"), 403

# Not Found
@errorBP.app_errorhandler(404)
def error404(e):
    return render_template("errors/404.html"), 404

# Method Not Allowed
@errorBP.app_errorhandler(405)
def error405(e):
    return render_template("errors/405.html"), 405

# Payload Too Large
@errorBP.app_errorhandler(413)
def error413(e):
    return render_template("errors/413.html"), 413

# I'm a Teapot
@errorBP.route("/teapot")
def teapot():
    abort(418)

@errorBP.app_errorhandler(418)
def error418(e):
    return render_template("errors/418.html"), 418

# Too Many Requests
@errorBP.app_errorhandler(429)
def error429(e):
    return render_template("errors/429.html"), 429

# Internal Server Error
@errorBP.app_errorhandler(500)
def error500(e):
    return render_template("errors/500.html"), 500

# Not Implemented
@errorBP.app_errorhandler(501)
def error501(e):
    return render_template("errors/501.html"), 501

# Bad Gateway
@errorBP.app_errorhandler(502)
def error502(e):
    return render_template("errors/502.html"), 502

# Service Temporarily Unavailable
@errorBP.app_errorhandler(503)
def error503(e):
    return render_template("errors/503.html"), 503