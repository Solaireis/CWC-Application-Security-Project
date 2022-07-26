# import python standard libraries
from time import time
from typing import Optional
from requests import get
from datetime import datetime
from json import dumps

# import third-party libraries
from flask import url_for
import stripe
from stripe.error import InvalidRequestError
from stripe.api_resources.checkout.session import Session as StripeCheckoutSession # Conflicts with Flask session
from css_inline import inline, CSSInliner # Not sure why VSC doesn't register these two

# import local python libraries
from python_files.classes.Constants import CONSTANTS
from .NormalFunctions import JWTExpiryProperties, send_email, generate_id
from .SQLFunctions import generate_limited_usage_jwt_token, sql_operation

stripe.api_key = CONSTANTS.STRIPE_SECRET_KEY

def stripe_product_create(
    courseID:str, courseName:str, courseDescription:str, coursePrice: float, courseImagePath:str=None
) -> None:
    """
    Create a product to add to Stripe database. 
    Provide matching details to what is saved in MySQL.

    Inputs:
    - courseID (str)
    - courseName (str)
    - courseDescription (str)
    - coursePrice (float)
    - courseImagePath (str)

    Output:
    None
    """
    try:
        courseData = stripe.Product.create(
            id = courseID,
            name = courseName,
            description = courseDescription,

            default_price_data = {
                "currency" : "USD",
                "unit_amount_decimal" : coursePrice * 100
            },
            images = [] if courseImagePath is None else [courseImagePath],
            url = url_for("generalBP.coursePage", _external = True, courseID = courseID)
        )

        # print(courseData)

    except InvalidRequestError as error:
        print(error)
        print(f"Course: {courseID} already exists in Stripe database.")

def stripe_product_update(**kwargs) -> None:
    courseID = kwargs.get('courseID')
    courseName = kwargs.get('courseName')
    courseDescription = kwargs.get('courseDescription')
    coursePrice = kwargs.get('coursePrice')
    courseImagePath = kwargs.get('courseImagePath')

    try:
        if (courseName):
            stripe.Product.modify(
                courseID,
                name = courseName,
            )
        if (courseDescription):
            stripe.Product.modify(
                courseID,
                description = courseDescription,
            )
        if (coursePrice):
            stripe.Product.modify(
                courseID,
                default_price_data = {
                    "currency" : "USD",
                    "unit_amount_decimal" : coursePrice * 100
                },
            )
        if (courseImagePath):
            stripe.Product.modify(
                courseID,
                images = [courseImagePath],
            )
    
    except:
        print("There was an Error in updating")

def stripe_product_deactivate(courseID:str):
    try:
        stripe.Product.modify(courseID, active = False)
    except InvalidRequestError as error:
        print(error)

#TODO: THIS
def stripe_product_edit(courseName=None, courseDescription = None, coursePrice = None, courseImagePath = None):
    pass

def stripe_product_check(courseID:str) -> Optional[str]:
    """
    Checks if a product exists on Stripe based on Course ID.

    Inputs:
    - courseID (str): CourseID of the course to check

    Output:
    - courseData (str, optional): Data about the course, in JSON format.
    """
    try:
        courseData = stripe.Product.retrieve(courseID)
        # print(courseData)
        return courseData
    except InvalidRequestError as error:
        print("Product Check: " + str(error))
        # print(f"Course {courseID} does not exist in Stripe database.")
        # print("Creating course in Stripe database.")
        return None

def stripe_checkout(userID: str, cartCourseIDs: list, email: str = None) -> Optional[StripeCheckoutSession]:
    """
    Create a checkout session in Stripe servers.
    Creates a JWT Token with userID and cartCourseIDs.

    Inputs:
    - userID (str)          : User ID to add payments to
    - cartCourseIDs (str)   : List of Course IDs in user cart to add to payments
    - email (str)           : Email field for Stripe checkout

    Output:
    - checkoutSession (StripeCheckoutSession)
        - checkout_session.id: id for reference
        - checkout_session.url: url to redirect to the Stripe server
        - Probably more...

    """
    paymentID = generate_id()
    expiryInfo = JWTExpiryProperties(activeDuration=3600)
    jwtToken = generate_limited_usage_jwt_token(payload={"userID": userID, "cartCourseIDs": cartCourseIDs, "paymentID":paymentID}, expiryInfo=expiryInfo)
    
    try:
        checkoutSession = stripe.checkout.Session.create(
            success_url = url_for("userBP.purchase", _external = True, jwtToken = jwtToken),
            cancel_url = url_for("userBP.shoppingCart", _external = True),
            customer_email = email,
            expires_at = int(time()) + 3600,
            line_items = [{"price": stripe_product_check(courseID).default_price, "quantity": 1} for courseID in cartCourseIDs],
            mode = "payment"
        )
        # print(checkoutSession)
        paymentIntent = stripe.PaymentIntent.retrieve(checkoutSession.payment_intent)

        sql_operation(
            table="stripe_payments", 
            mode="create_payment_session", 
            paymentID = paymentID,
            stripePaymentIntent = checkoutSession.payment_intent,
            userID = userID,
            cartCourseIDs = dumps(cartCourseIDs),
            createdTime = datetime.fromtimestamp(paymentIntent["created"]).strftime('%Y-%m-%d %H:%M:%S'),
            amount = round(paymentIntent["amount"]/100, 2)
        )

        return checkoutSession

    except Exception as error:
         print("Checkout: " + str(error))
         return None

def expire_checkout(checkoutSession:str) -> None:
    """
    Expires a checkout session.
    (e.g. shopping cart is altered while checkout is still active.)
    Inputs:
    - 

    Output:
    - None
    """
    try:
        stripe.checkout.Session.expire(checkoutSession)
    except InvalidRequestError:
        print(f"Session {checkoutSession} has already expired.")

def send_checkout_receipt(paymentID):
    paymentIntent = sql_operation(table="stripe_payments", mode="get_payment_intent", paymentID=paymentID)

    checkoutDetails = stripe.PaymentIntent.retrieve(paymentIntent)["charges"]["data"][0]
    send_email(
        to = checkoutDetails["receipt_email"], 
        subject = f"Your CourseFinity receipt [#{checkoutDetails['receipt_number']}]",
        body = CSSInliner(remove_style_tags=True).inline(get(checkoutDetails["receipt_url"]).text).split("</head>", 1)[1][:-7],
        name = checkoutDetails["billing_details"]["name"]
    )

    sql_operation(
        table = "stripe_payments", 
        mode = "complete_payment_session", 
        paymentID = paymentID, 
        paymentTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        receiptEmail = checkoutDetails["receipt_email"]
    )


"""
Expire session:
# print(expire_checkout('cs_test_b17DWUoKPuzeXE5h7Y4Ubd0aMPhO4K7CiDjqTxVXddouKueDfNtqoFYx5z'))

Create courses if they don't exist:
# for num in range(1, 6):
#    if stripe_product_check(courseID = f"Test_Course_ID_{num}_v2") is None:
#        stripe_product_create(f"Test_Course_ID_{num}_v2", f"Test Course Name {num}", f"Test Course Description {num}", num*100, None, debug = True)

Create checkout session (and print returned data):
# print(stripe_checkout(userID = "Test_User", cartCourseIDs = [f"Test_Course_ID_{num}_v2" for num in range(1, 6)], email = "test@email.com", debug = True))

Send receipt:
send_checkout_receipt("pi_3LPmRrEQ13luXvBj0pCCIO9h")
"""