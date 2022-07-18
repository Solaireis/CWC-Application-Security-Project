# import flask libraries (Third-party libraries)
from flask_seasurf import SeaSurf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import current_app

"""
For creating a SeaSurf object to customise the csrf protection without initialising the web app.
This helps prevent circular imports.

Refer to docs: https://flask-seasurf.readthedocs.io/en/1.1.1/
Usage example below:

from python_files.Constants import CONSTANTS
from .RoutesSecurity import csrf

@csrf.exempt
@blueprintObj.route("/demo", methods=["GET", "POST"])
def routeFn():
    ...
"""
csrf = SeaSurf()

"""
For creating a limiter object to customise the rate limiters without initialising the web app.
This helps prevent circular imports.

Refer to docs: https://flask-limiter.readthedocs.io/en/stable/
Usage example below:

from python_files.Constants import CONSTANTS
from .RoutesSecurity import limiter
limiter.limit(limit_value=CONSTANTS.REQUEST_LIMIT)(blueprintObj)

@blueprintObj.route("/demo")
@limiter.limit("10 per second")
def routeFn():
    ...
"""
limiter = Limiter(key_func=get_remote_address, default_limits=[current_app.config["CONSTANTS"].REQUEST_LIMIT])