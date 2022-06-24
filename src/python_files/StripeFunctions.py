# import python standard libraries
from pathlib import Path
from flask import url_for
from time import time
from json import loads

# import third-party libraries
import stripe
from stripe.error import InvalidRequestError

# import Authlib [JWT] modules (third-party libraries)
from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError

# import local python libraries
from .ConstantsInit import STRIPE_SECRET_KEY, STRIPE_PUBLIC_KEY

stripe.api_key = STRIPE_SECRET_KEY

# since the .json file is not shared yet, will comment it out for now
# with open(Path(__file__).parent.parent.joinpath("config_files/jwt-keys.json")) as jwtKeys:
#     jwtKeys = loads(jwtKeys.read())

#     private = jwtKeys["private"]
#     public = jwtKeys["public"]

def stripe_product_create(courseID, courseName, courseDescription, coursePrice, courseImagePath, debug=False) -> None:
    if debug:
        courseUrl = "https://example.com"
    else:
        courseUrl = url_for("coursePage", courseID = courseID)

    try:
        courseData = stripe.Product.create(
            id = courseID,
            name = courseName,
            description = courseDescription,
            
            default_price_data = {
                "currency" : "USD",
                "unit_amount_decimal" : coursePrice
            },
            images = [courseImagePath],
            url = courseUrl
        )

        print(courseData)

    except InvalidRequestError as error:
        print(error)
        print(f"Course: {courseID} already exists in Stripe database.")       

def stripe_product_check(courseID):
    try:
        courseData = stripe.Product.retrieve(courseID)
        print(courseData)
        return courseData
    except InvalidRequestError as error:
        print("Product Check: " + str(error))
        # print(f"Course {courseID} does not exist in Stripe database.")
        # print("Creating course in Stripe database.")
        return None

def stripe_checkout(userID: str, cartCourseIDs: list, email: str, debug=False) -> None:
    if debug:
        success_url = cancel_url = "http://127.0.0.1:8080"
    else:
        success_url = url_for("purchaseHistory")
        cancel_url = url_for("cart")

    try:
        checkoutSession = stripe.checkout.Session.create(
            success_url = success_url,
            cancel_url = cancel_url,
            customer_email = email,
            expires_at = int(time()) + 3600,
            line_items = [{"price": stripe_product_check(courseID).default_price, "quantity": 1} for courseID in cartCourseIDs],
            mode = "payment"
        )
        print(checkoutSession)
        return checkoutSession.url

    except Exception as error:
        print("Checkout: " + str(error))

def expire_checkout():  # In the event shopping cart is altered while checkout is still active; Insecure Design
    pass

def generate_jwt(userID:str, activeDuration:int=60) -> bytes: # JSON Web Token

    if activeDuration is not None:
        activeDuration = int(time() + activeDuration)

    token = jwt.encode(header = {"alg": "RS256"}, payload = {"userID": userID, "expiry": activeDuration}, key = private)
    return token

def decrypt_jwt(token) -> str:
    try:
        token = jwt.decode(s = token, key = public)
    except BadSignatureError as error: # Incorrect key/tampered token
        print(error)

    print(token["expiry"])

    if token["expiry"] is not None:
        if token["expiry"] > time():
            print("Token not expired")

    return token
if __name__ == "__main__":
    token = generate_jwt("Test_User")
    print(token)
    # token = sub(b"a", b"b", token)    # Simulate tampered token
    print(token)

    print(decrypt_jwt(token))
    """
    for num in range(1, 6):
        if stripe_product_check(courseID = f"Test_Course_ID_{num}_v2") is None:
            stripe_product_create(f"Test_Course_ID_{num}_v2", f"Test Course Name {num}", f"Test Course Description {num}", num*100, None, debug = True)
    print(stripe_checkout(userID = "Test_User", cartCourseIDs = [f"Test_Course_ID_{num}_v2" for num in range(1, 6)], email = "test@email.com", debug = True))
    """