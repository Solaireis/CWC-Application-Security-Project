# import python standard libraries
from pathlib import Path
from flask import url_for
from time import time

# import third-party libraries
import stripe
from stripe.error import InvalidRequestError
from inspect import stack, getframeinfo

# import local python libraries
if Path(getframeinfo(stack()[-1][0]).filename).stem != 'app':
    from Constants import CONSTANTS
    from NormalFunctions import EC_sign, JWTExpiryProperties
else:
    from .Constants import CONSTANTS
    from .NormalFunctions import EC_sign, JWTExpiryProperties

stripe.api_key = CONSTANTS.STRIPE_SECRET_KEY

def stripe_product_create(courseID, courseName, courseDescription, coursePrice, courseImagePath=None, debug=False) -> None:
    if debug:
        courseUrl = "https://example.com"
    else:
        courseUrl = url_for("generalBP.coursePage", _external = True, courseID = courseID)

    if courseImagePath is None:
        images = []
    else:
        images = [courseImagePath]

    try:
        courseData = stripe.Product.create(
            id = courseID,
            name = courseName,
            description = courseDescription,

            default_price_data = {
                "currency" : "USD",
                "unit_amount_decimal" : coursePrice
            },
            images = images,
            url = courseUrl
        )

        # print(courseData)

    except InvalidRequestError as error:
        print(error)
        print(f"Course: {courseID} already exists in Stripe database.")

def stripe_product_check(courseID):
    try:
        courseData = stripe.Product.retrieve(courseID)
        # print(courseData)
        return courseData
    except InvalidRequestError as error:
        print("Product Check: " + str(error))
        # print(f"Course {courseID} does not exist in Stripe database.")
        # print("Creating course in Stripe database.")
        return None

def stripe_checkout(userID: str, cartCourseIDs: list, email: str, debug=False) -> str:
    print(url_for("userBP.purchase", _external = True, userToken = EC_sign(payload = userID, keyID = 'signing-key', b64EncodeData = True, expiry = JWTExpiryProperties(activeDuration = 3600))))
    if debug:
        success_url = cancel_url = "http://127.0.0.1:8080"
    else:
        success_url = url_for("userBP.purchase", _external = True, userToken = EC_sign(payload = userID, keyID = 'signing-key', b64EncodeData = True, expiry = JWTExpiryProperties(activeDuration = 3600)))
        cancel_url = url_for("userBP.cart", _external = True)

    print(type(success_url))

#    try:
    checkoutSession = stripe.checkout.Session.create(
        success_url = success_url,
        cancel_url = cancel_url,
        customer_email = email,
        expires_at = int(time()) + 3600,
        line_items = [{"price": stripe_product_check(courseID).default_price, "quantity": 1} for courseID in cartCourseIDs],
        mode = "payment"
    )
    # print(checkoutSession)
    return checkoutSession

#    except Exception as error:
#        print("Checkout: " + str(error))
#        return None

def expire_checkout(checkoutSession):  # In the event shopping cart is altered while checkout is still active; Insecure Design
    stripe.checkout.Session.expire(checkoutSession)

if __name__ == "__main__":
    for num in range(1, 6):
        if stripe_product_check(courseID = f"Test_Course_ID_{num}_v2") is None:
            stripe_product_create(f"Test_Course_ID_{num}_v2", f"Test Course Name {num}", f"Test Course Description {num}", num*100, None, debug = True)
    print(stripe_checkout(userID = "Test_User", cartCourseIDs = [f"Test_Course_ID_{num}_v2" for num in range(1, 6)], email = "test@email.com", debug = True))
