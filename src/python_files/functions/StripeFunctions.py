# import python standard libraries
from time import time

# import third-party libraries
from flask import url_for
import stripe
from stripe.error import InvalidRequestError

# import local python libraries
from python_files.classes.Constants import CONSTANTS
from .NormalFunctions import EC_sign, JWTExpiryProperties
from .SQLFunctions import generate_limited_usage_jwt_token

stripe.api_key = CONSTANTS.STRIPE_SECRET_KEY

def stripe_product_create(
    courseID:str, courseName:str, courseDescription:str, coursePrice: float, courseImagePath:str=None
) -> None:
    try:
        courseData = stripe.Product.create(
            id = courseID,
            name = courseName,
            description = courseDescription,

            default_price_data = {
                "currency" : "USD",
                "unit_amount_decimal" : coursePrice
            },
            images = [] if courseImagePath is None else [courseImagePath],
            url = url_for("generalBP.coursePage", _external = True, courseID = courseID)
        )

        # print(courseData)

    except InvalidRequestError as error:
        print(error)
        print(f"Course: {courseID} already exists in Stripe database.")

def stripe_product_check(courseID:str):
    try:
        courseData = stripe.Product.retrieve(courseID)
        # print(courseData)
        return courseData
    except InvalidRequestError as error:
        print("Product Check: " + str(error))
        # print(f"Course {courseID} does not exist in Stripe database.")
        # print("Creating course in Stripe database.")
        return None

def stripe_checkout(userID: str, cartCourseIDs: list, email: str) -> str:
    expiryInfo = JWTExpiryProperties(activeDuration=3600)
    jwtToken = generate_limited_usage_jwt_token(payload={"userID": userID, "cartCourseIDs": cartCourseIDs}, expiryInfo=expiryInfo)
    try:
        checkoutSession = stripe.checkout.Session.create(
            success_url = url_for("userBP.purchase", _external = True, jwtToken = jwtToken),
            cancel_url = url_for("userBP.cart", _external = True),
            customer_email = email,
            expires_at = int(time()) + 3600,
            line_items = [{"price": stripe_product_check(courseID).default_price, "quantity": 1} for courseID in cartCourseIDs],
            mode = "payment"
        )
        # print(checkoutSession)
        return checkoutSession

    except Exception as error:
         print("Checkout: " + str(error))
         return None

def expire_checkout(checkoutSession:str) -> None:  # In the event shopping cart is altered while checkout is still active; Insecure Design
    try:
        stripe.checkout.Session.expire(checkoutSession)
    except InvalidRequestError:
        print(f"Session {checkoutSession} has already expired.")

"""
Expire session:
# print(expire_checkout('cs_test_b17DWUoKPuzeXE5h7Y4Ubd0aMPhO4K7CiDjqTxVXddouKueDfNtqoFYx5z'))

Create courses if they don't exist:
# for num in range(1, 6):
#    if stripe_product_check(courseID = f"Test_Course_ID_{num}_v2") is None:
#        stripe_product_create(f"Test_Course_ID_{num}_v2", f"Test Course Name {num}", f"Test Course Description {num}", num*100, None, debug = True)

Create checkout session (and print returned data):
# print(stripe_checkout(userID = "Test_User", cartCourseIDs = [f"Test_Course_ID_{num}_v2" for num in range(1, 6)], email = "test@email.com", debug = True))
"""