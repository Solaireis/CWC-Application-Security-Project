"""
For creating a limiter object to customise the rate limiters without initialising the app.
This helps prevent circular imports.

Usage example below:

from python_files.Constants import CONSTANTS
from .RoutesLimiter import limiter
limiter.limit(limit_value=CONSTANTS.REQUEST_LIMIT)(blueprintObj)

@blueprintObj.route("/demo")
@limiter.limit("10 per second")
def routeFn():
    ...
"""
# import flask libraries (Third-party libraries)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["30 per second"])