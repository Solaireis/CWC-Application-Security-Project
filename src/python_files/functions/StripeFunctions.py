# import python standard libraries
from time import time
from typing import Optional
import requests
from datetime import datetime
from json import dumps

# import third-party libraries
from flask import url_for
import stripe
from stripe.error import InvalidRequestError
from stripe.api_resources.checkout.session import Session as CheckoutSession # Conflicts with Flask session
from stripe.api_resources.payment_intent import PaymentIntent
from css_inline import inline, CSSInliner # Not sure why VSC doesn't register these two

# import local python libraries
from python_files.classes.Constants import SECRET_CONSTANTS, CONSTANTS
from .NormalFunctions import send_email
from .SQLFunctions import sql_operation

stripe.api_key = SECRET_CONSTANTS.STRIPE_SECRET_KEY

def stripe_product_create(
    courseID:str, courseName:str, courseDescription:str, coursePrice: float, courseImagePath:str=None
) -> None:
    """
    Create a product to add to Stripe database. 
    Provide matching details to what is saved in MySQL.

    Args:
    - courseID (str)
    - courseName (str)
    - courseDescription (str)
    - coursePrice (float)
    - courseImagePath (str)

    Returns:
    - None
    """
    try:
        courseData = stripe.Product.create(
            id=courseID,
            name=courseName,
            description=courseDescription,

            default_price_data={
                "currency" : "USD",
                "unit_amount_decimal" : coursePrice * 100
            },
            images=[] if courseImagePath is None else [courseImagePath],
            url=f"{CONSTANTS.CUSTOM_DOMAIN}{url_for('generalBP.coursePage', courseID = courseID)}"
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
                name=courseName,
            )
        if (courseDescription):
            stripe.Product.modify(
                courseID,
                description=courseDescription,
            )
        if (coursePrice):
            stripe.Product.modify(
                courseID,
                default_price_data={
                    "currency" : "USD",
                    "unit_amount_decimal" : coursePrice * 100
                },
            )
        if (courseImagePath):
            stripe.Product.modify(
                courseID,
                images=[courseImagePath],
            )
    
    except:
        print("There was an Error in updating")

def stripe_product_deactivate(courseID:str) -> None:
    try:
        stripe.Product.modify(courseID, active = False)
    except InvalidRequestError as error:
        print(error)

def stripe_product_check(courseID:str) -> Optional[str]:
    """
    Checks if a product exists on Stripe based on Course ID.

    Args:
    - courseID (str): CourseID of the course to check

    Returns:
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

def stripe_checkout(userID: str, cartCourseIDs: list, email: str = None) -> Optional[CheckoutSession]:
    """
    Create a checkout session in Stripe servers.
    Creates a JWT Token with userID and cartCourseIDs.

    Args:
    - userID (str)          : User ID to add payments to
    - cartCourseIDs (str)   : List of Course IDs in user cart to add to payments
    - email (str)           : Email field for Stripe checkout

    Returns:
    - checkoutSession (StripeCheckoutSession)
        - checkout_session.id: id for reference
        - checkout_session.url: url to redirect to the Stripe server
        - Probably more...
    """
    paymentIntent = sql_operation(table="stripe_payments", mode="pop_previous_session", userID=userID)
    print("Old Payment Intent:", paymentIntent)
    if paymentIntent is not None:
        checkoutID = stripe.PaymentIntent.retrieve(paymentIntent).metadata["checkoutID"]
        expire_checkout(checkoutID)

    try:
        checkoutSession = stripe.checkout.Session.create(
            success_url=f"{CONSTANTS.CUSTOM_DOMAIN}{url_for('userBP.purchase', userID=userID)}",
            cancel_url=f"{CONSTANTS.CUSTOM_DOMAIN}{url_for('userBP.shoppingCart')}",
            customer_email=email,
            expires_at=int(time()) + 3600,
            line_items=[{"price": stripe_product_check(courseID).default_price, "quantity": 1} for courseID in cartCourseIDs],
            mode="payment"
        )
    except Exception as error:
        print("Checkout:", str(error))
        # print(type(checkoutSession))
        return None
    print(cartCourseIDs)
    print("Checkout Session Created:", checkoutSession.payment_intent)
    paymentIntent = stripe.PaymentIntent.retrieve(checkoutSession.payment_intent)
    stripe.PaymentIntent.modify(checkoutSession.payment_intent, metadata = {
        "checkoutID": checkoutSession.id,
        "userID": userID, 
        "cartCourseIDs": dumps(cartCourseIDs),
        "coursesAdded": False
    })
    print("Payment Intent Modified")
    sql_operation(
        table="stripe_payments", 
        mode="create_payment_session", 
        stripePaymentIntent=checkoutSession.payment_intent,
        userID=userID,
        cartCourseIDs=dumps(cartCourseIDs),
        createdTime=datetime.fromtimestamp(paymentIntent["created"]).strftime('%Y-%m-%d %H:%M:%S'),
        amount=round(paymentIntent["amount"]/100, 2)
    )
    print("SQL Success")
    return checkoutSession

def expire_checkout(checkoutSession:str) -> None:
    """
    Expires a checkout session.
    (e.g. shopping cart is altered while checkout is still active.)

    Args:
    - 

    Returns:
    - None
    """
    try:
        stripe.checkout.Session.expire(checkoutSession)
        print(f"Session expired: {checkoutSession}")
    except InvalidRequestError:
        print(f"Session already expired: {checkoutSession}")

def send_checkout_receipt(paymentIntent:str) -> None:

    checkoutDetails = stripe.PaymentIntent.retrieve(paymentIntent)["charges"]["data"][0]
    send_email(
        to=checkoutDetails["receipt_email"], 
        subject=f"Your CourseFinity receipt [#{checkoutDetails['receipt_number']}]",
        body=CSSInliner(remove_style_tags=True).inline(requests.get(checkoutDetails["receipt_url"]).text).split("</head>", 1)[1][:-7],
        name=checkoutDetails["billing_details"]["name"]
    )

    sql_operation(
        table="stripe_payments", 
        mode="complete_payment_session", 
        stripePaymentIntent=paymentIntent, 
        paymentTime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        receiptEmail=checkoutDetails["receipt_email"]
    )

def get_payment_intent(paymentIntent:str) -> PaymentIntent:
    return stripe.PaymentIntent.retrieve(paymentIntent)

# print(get_payment_intent("pi_3LPmRrEQ13luXvBj0pCCIO9h"))

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