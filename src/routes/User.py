"""
Routes for logged in normal users (Students or Teachers)
"""
# import third party libraries
from werkzeug.utils import secure_filename
import markdown

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, current_app, send_from_directory

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.functions.StripeFunctions import *
from python_files.functions.VimeoFunctions import *
from python_files.classes.Forms import *
from python_files.classes.MarkdownExtensions import AnchorTagPreExtension, AnchorTagPostExtension

# import python standard libraries
from pathlib import Path
from io import BytesIO

userBP = Blueprint("userBP", __name__, static_folder="static", template_folder="template")

@userBP.route("/user-profile", methods=["GET","POST"])
def userProfile():
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)

        username = userInfo.username
        email = userInfo.email
        loginViaGoogle = userInfo.googleOAuth
        twoFAEnabled = userInfo.hasTwoFA
        """
        Updates to teacher but page does not change, requires refresh
        """
        return render_template("users/loggedin/user_profile.html", username=username, email=email, imageSrcPath=userInfo.profileImage, twoFAEnabled=twoFAEnabled, loginViaGoogle=loginViaGoogle, accType=userInfo.role)
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/change-email", methods=["GET","POST"])
def updateEmail():
    if ("user" in session):
        userID = session["user"]
        userInfo = get_image_path(userID, returnUserInfo=True)
        oldEmail = userInfo.email

        # check if user logged in via Google OAuth2
        loginViaGoogle = userInfo.googleOAuth
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
                return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
            else:
                print(f"old email:{oldEmail}, new email:{updatedEmail}")
                flash(
                    "Your email has been successfully changed. However, a link has been sent to your new email to verify your new email!",
                    "Account Details Updated!"
                )
                return redirect(url_for("userBP.userProfile"))
        else:
            return render_template("users/loggedin/change_email.html", form=create_update_email_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
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
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        if ("https://storage.googleapis.com/coursefinity" in userInfo.profileImage):
            sql_operation(table="user", mode="delete_profile_picture", userID=userInfo.uid)
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

    #get course data 
    course=sql_operation(table="course", mode="get_course_data", courseID=courseID)

    #get user data
    if ("user" in session):
        print("user is logged in")
        userID=session["user"]
        purchases=sql_operation(table="user", mode="get_user_purchases", userID=userID)
    
        purchased = False

        #i think there exist a better way to secure this
        for items in purchases:
            if (items.courseID==courseID):
                purchased = True

        if purchased:
                print("user has purchased this course")
                return render_template("users/loggedin/purchase_review.html", course=course, userID=userID)
        else:
            print("user has not purchased this course")
            return render_template("users/loggedin/purchase_review.html", course=course, userID=userID)

    else:
        return redirect(url_for("guestBP.login"))


@userBP.route("/submit-review", methods=["GET","POST"])
def submitReview():
    pass


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

    teacherRecords = get_image_path(courses.teacherID, returnUserInfo=True)
    print(teacherRecords)

    accType = imageSrcPath = None
    userPurchasedCourses = {}
    if ("user" in session):
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = userInfo.uid
        accType = userInfo.role
        imageSrcPath = userInfo.profileImage

    return render_template("users/general/purchase_view.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherRecords.username, teacherProfilePath=teacherRecords.profileImage, courseDescription=courseDescription, courseVideoPath=courseVideoPath, accType=accType)

@userBP.post("/add_to_cart/<string:courseID>")
def addToCart(courseID:str):
    if ("user" in session):
        sql_operation(table="user", mode="add_to_cart", userID=session["user"], courseID=courseID)
        return redirect(url_for("userBP.shoppingCart"))
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
            userInfo = get_image_path(userID, returnUserInfo=True)
            # print(userInfo)
            cartCourseIDs = userInfo.cartCourses

            courseList = []
            subtotal = 0

            # TODO: Could have used Course.py's class instead of
            # TODO: manually retrieving the data from the tuple
            for courseID in cartCourseIDs:
                course = sql_operation(table='course', mode = "get_course_data", courseID = courseID)
                courseList.append(course)
                subtotal += course.coursePrice

            return render_template("users/loggedin/shopping_cart.html", courseList=courseList, subtotal=f"{subtotal:,.2f}", imageSrcPath=userInfo.profileImage, accType=userInfo.role)

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
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        print(userInfo)
        purchasedCourseIDs = userInfo.purchasedCourses
        courseList = []

        # TODO: Could have used Course.py's class instead of
        # TODO: manually retrieving the data from the tuple
        for courseID in purchasedCourseIDs:
            course = sql_operation(table="course", mode="get_course_data", courseID=courseID)
            print(course)
            if course != False:
                courseList.append(course)

        return render_template("users/loggedin/purchase_history.html", courseList=courseList, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
    else:
        return redirect(url_for('guestBP.login'))