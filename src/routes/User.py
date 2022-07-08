"""
Routes for logged in normal users (Students or Teachers)
"""
# import third party libraries
from werkzeug.utils import secure_filename
import markdown

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, current_app

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.functions.StripeFunctions import *
from python_files.functions.VimeoFunctions import *
from python_files.classes.Forms import *
from python_files.classes.MarkdownExtensions import AnchorTagPreExtension, AnchorTagPostExtension

# import python standard libraries
from datetime import datetime
from pathlib import Path
from io import BytesIO
from json import loads

userBP = Blueprint("userBP", __name__, static_folder="static", template_folder="template")

@userBP.route("/user-profile", methods=["GET","POST"])
def userProfile():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)

        username = userInfo[2]
        email = userInfo[3]
        loginViaGoogle = True if (userInfo[5] is None) else False # check if the password is NoneType

        twoFAEnabled = False
        if (not loginViaGoogle):
            twoFAEnabled = sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userInfo[0])

        """
        Updates to teacher but page does not change, requires refresh
        """

        return render_template("users/loggedin/user_profile.html", username=username, email=email, imageSrcPath=imageSrcPath, twoFAEnabled=twoFAEnabled, loginViaGoogle=loginViaGoogle, accType=userInfo[1])
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/change-email", methods=["GET","POST"])
def updateEmail():
    if ("user" in session):
        userID = session["user"]
        imageSrcPath, userInfo = get_image_path(userID, returnUserInfo=True)
        oldEmail = userInfo[2]

        # check if user logged in via Google OAuth2
        loginViaGoogle = True if (userInfo[5] is None) else False # check if the password is NoneType
        if (loginViaGoogle):
            # if so, redirect to user profile as they cannot change their email
            return redirect(url_for("userBP.userProfile"))

        create_update_email_form = CreateChangeEmail(request.form)
        if (request.method == "POST") and (create_update_email_form.validate()):
            updatedEmail = create_update_email_form.updateEmail.data
            currentPassword = create_update_email_form.currentPassword.data

            changed = False
            try:
                sql_operation(table="user", mode="change_email", userID=userID, email=updatedEmail, currentPassword=currentPassword)
                changed = True
            except (EmailAlreadyInUseError):
                flash("Sorry, email has already been taken!")
            except (SameAsOldEmailError):
                flash("Sorry, please enter a different email from your current one!")
            except (IncorrectPwdError):
                flash("Sorry, please check your current password and try again!")

            if (not changed):
                return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
            else:
                print(f"old email:{oldEmail}, new email:{updatedEmail}")
                flash(
                    "Your email has been successfully changed. However, a link has been sent to your new email to verify your new email!",
                    "Account Details Updated!"
                )
                return redirect(url_for("userBP.userProfile"))
        else:
            return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("guestBP.login"))

@userBP.post("/change-account-type")
def changeAccountType():
    if ("admin" in session):
        return redirect(url_for("adminBP.adminProfile"))

    if ("user" in session):
        userID = session["user"]
        if (request.form["changeAccountType"] == "changeToTeacher"):
            try:
                sql_operation(table="user", mode="update_to_teacher", userID=userID)
                flash("Your account has been successfully upgraded to a Teacher.", "Account Details Updated!")
            except (IsAlreadyTeacherError):
                flash("You are already a teacher!", "Failed to Update!")
            return redirect(url_for("userBP.userProfile"))
        else:
            print("Did not have relevant hidden field.")
            return redirect(url_for("userBP.userProfile"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.post("/delete-profile-picture")
def deletePic():
    if ("admin" in session):
        return redirect(url_for("adminBP.adminProfile"))

    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        if ("https://storage.googleapis.com/coursefinity" in imageSrcPath):
            sql_operation(table="user", mode="delete_profile_picture", userID=userInfo[0])
            flash("Your profile picture has been successfully deleted.", "Profile Picture Deleted!")
        return redirect(url_for("userBP.userProfile"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.post("/upload-profile-picture")
def uploadPic():
    if ("admin" in session):
        return redirect(url_for("adminBP.adminProfile"))

    if ("user" in session):
        userID = session["user"]
        if ("profilePic" not in request.files):
            print("No File Sent")
            return redirect(url_for("userBP.userProfile"))

        file = request.files["profilePic"]
        filename = secure_filename(file.filename)
        if (filename == "" or not accepted_image_extension(filename)):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Profile Image!")
            return redirect(url_for("userBP.userProfile"))

        filePath = Path(generate_id(sixteenBytesTimes=2) + Path(filename).suffix)
        imageData = BytesIO(file.read())
        try:
            imageUrlToStore = compress_and_resize_image(
                imageData=imageData, imagePath=filePath, dimensions=(500, 500), 
                folderPath=f"user-profiles"
            )
        except (InvalidProfilePictureError):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Profile Image!")
            return redirect(url_for("userBP.userProfile"))
        except (UploadFailedError):
            flash(Markup("Sorry, there was an error uploading your profile picture...<br>Please try again later!"), "Failed to Upload Profile Image!")
            return redirect(url_for("userBP.userProfile"))

        sql_operation(table="user", mode="change_profile_picture", userID=userID, profileImagePath=imageUrlToStore)
        flash(Markup("Your profile picture has been successfully uploaded.<br>If your profile picture has not changed on your end, please wait or clear your browser cache to see the changes."), "Profile Picture Uploaded!")
        return redirect(url_for("userBP.userProfile"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/course-review/<string:courseID>") #writing of review
def courseReview(courseID:str):

    course=sql_operation(table="course", mode="get_course_data", courseID=courseID)

    if ("user" in session):
        pass

    return render_template("users/general/course_page_review.html",
        course=course)

@userBP.route("/purchase-view/<string:courseID>")
def purchaseView(courseID:str):
    # TODO: Make the argument based on the purchaseID instead of courseID
    print(courseID)
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    print(courses)
    #courseName = courses[0][1]
    if courses == False: #raise 404 error
        abort(404)

    # TODO: Could have used Course.py's class instead of
    # TODO: manually retrieving the data from the tuple
    #create variable to store these values
    courseDescription = Markup(
        markdown.markdown(
            courses.courseDescription,
            extensions=[AnchorTagPreExtension(), AnchorTagPostExtension()]
        )
    )

    courseVideoPath = None


    teacherProfilePath = get_image_path(courses.teacherID)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=courses.teacherID)
    print(teacherRecords)
    teacherName = teacherRecords[2]

    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo[-1]
        accType = userInfo[1]

    return render_template("users/general/purchase_view.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherName, teacherProfilePath=teacherProfilePath \
        , courseDescription=courseDescription, courseVideoPath=courseVideoPath, accType=accType)

@userBP.post("/add_to_cart/<string:courseID>")
def addToCart(courseID:str):
    if ("user" in session):
        sql_operation(table="user", mode="add_to_cart", userID=session["user"], courseID=courseID)
        return redirect(url_for("userBP.cart"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/shopping-cart", methods=["GET", "POST"])
def shoppingCart():
    print(str(session))
    if "user" in session:
        userID = session["user"]
        if request.method == "POST":
            # Remove item from cart
            courseID = request.form.get("courseID")
            sql_operation(table="user", mode="remove_from_cart", userID=userID, courseID=courseID)

            return redirect(url_for("userBP.cart"))

        else:
            imageSrcPath, userInfo = get_image_path(userID, returnUserInfo=True)
            # print(userInfo)
            cartCourseIDs = loads(userInfo[-2])

            courseList = []
            subtotal = 0

            # TODO: Could have used Course.py's class instead of
            # TODO: manually retrieving the data from the tuple
            for courseID in cartCourseIDs:
                course = sql_operation(table='course', mode = "get_course_data", courseID = courseID)
                courseList.append({
                    "courseID" : course[0],
                    "courseOwnerLink" : url_for("generalBP.teacherPage", teacherID=course[1]), # course[1] is teacherID
                    "courseOwnerUsername" : sql_operation(table="user", mode="get_user_data", userID=course[1])[2],
                    "courseOwnerImagePath" : get_image_path(course[1]),
                    "courseName" : course[2],
                    "courseDescription" : course[3],
                    "courseThumbnailPath" : course[4],
                    "coursePrice" : f"{course[5]:,.2f}",
                })
                subtotal += course[5]

            return render_template("users/loggedin/shopping_cart.html", courseList=courseList, subtotal=f"{subtotal:,.2f}", imageSrcPath=imageSrcPath, accType=userInfo[1])

    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/checkout", methods = ["GET", "POST"])
def checkout():
    if 'user' in session:
        userID = session["user"]

        cartCourseIDs = sql_operation(table='user', mode = 'get_user_cart', userID = userID)
        email = sql_operation(table = 'user', mode = 'get_user_data', userID = userID)[3]
        print(cartCourseIDs)
        print(email)

        try:
            checkout_session = stripe_checkout(userID = userID, cartCourseIDs = cartCourseIDs, email = email)
        except Exception as error:
            print(str(error))
            return redirect(url_for('userBP.cart'))

        print(checkout_session)
        print(type(checkout_session))

        return redirect(checkout_session.url, code = 303) # Stripe says use 303, we shall stick to 303
    else:
        return redirect(url_for('guestBP.login'))

@userBP.route("/purchase/<string:jwtToken>")
def purchase(jwtToken:str):
    data = EC_verify(jwtToken, getData = True)

    if not data.get("verified"):
        abort(400)

    tokenID = data["header"].get("token_id")
    if (tokenID is None):
        abort(404)

    if not sql_operation(table="limited_use_jwt", mode="jwt_is_valid", tokenID=tokenID):
        abort(400)

    sql_operation(table="limited_use_jwt", mode="decrement_limit_after_use", tokenID=tokenID)

    payload = data['data']['payload']
    tokenCartCourseIDs = payload.get('cartCourseIDs') # The courses paid for,
    tokenUserID = payload.get('userID')               # To the person who generated the payment.

    sql_operation(table="user", mode="purchase_courses", userID = tokenUserID, cartCourseIDs = tokenCartCourseIDs)
    return redirect(url_for("userBP.purchaseHistory"))

@userBP.route("/purchase-history")
def purchaseHistory():
    if 'user' in session:
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        print(userInfo)
        purchasedCourseIDs = loads(userInfo[-1])
        courseList = []

        # TODO: Could have used Course.py's class instead of
        # TODO: manually retrieving the data from the tuple
        for courseID in purchasedCourseIDs:
            course = sql_operation(table="course", mode="get_course_data", courseID=courseID)
            print(course)
            if course != False:
                courseList.append(course)

        return render_template("users/loggedin/purchase_history.html", courseList=courseList, imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for('guestBP.login'))

# blocks all user from viewing the video so that they are only allowed to view the video from the purchase view
@userBP.route("/static/course_videos/<path:filename>")
def blockAccess(filename):
    abort(403)