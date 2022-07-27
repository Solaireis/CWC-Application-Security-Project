"""
Routes for logged in normal users (Students or Teachers)
"""
# import third party libraries
from werkzeug.utils import secure_filename
from flask_limiter.util import get_remote_address
import markdown, pyotp, qrcode, html, hashlib

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, make_response

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.functions.StripeFunctions import *
from python_files.classes.Forms import *
from python_files.classes.MarkdownExtensions import AnchorTagExtension
from .RoutesSecurity import csrf

# import python standard libraries
from pathlib import Path
from io import BytesIO
from base64 import b64encode

userBP = Blueprint("userBP", __name__, static_folder="static", template_folder="template")

@userBP.route("/user-profile", methods=["GET","POST"])
def userProfile():
    userInfo = get_image_path(session["user"], returnUserInfo=True)

    username = userInfo.username
    email = userInfo.email
    loginViaGoogle = userInfo.googleOAuth
    twoFAEnabled = userInfo.hasTwoFA
    """
    Updates to teacher but page does not change, requires refresh
    """
    return render_template("users/user/user_profile.html", username=username, email=email, imageSrcPath=userInfo.profileImage, twoFAEnabled=twoFAEnabled, loginViaGoogle=loginViaGoogle, accType=userInfo.role)

@userBP.route("/setup-2fa", methods=["GET", "POST"])
def twoFactorAuthSetup():
    userID = session["user"]
    userInfo = get_image_path(userID, returnUserInfo=True)

    # check if user logged in via Google OAuth2
    if (userInfo.googleOAuth == True):
        # if so, redirect to user profile as the authentication security is handled by Google themselves
        flash(Markup("You had signed up with Google OAuth2 on CourseFinity.<br>Please <a href='https://support.google.com/accounts/answer/185839?hl=en' target='_blank' rel='noopener noreferrer'>setup 2FA for your Google account</a> instead!"))
        return redirect(url_for("userBP.userProfile"))

    # check if user has already setup 2fa
    if (userInfo.hasTwoFA):
        return redirect(url_for("userBP.userProfile"))

    twoFactorAuthForm = twoFAForm(request.form)
    if (request.method == "GET"):
        # for google authenticator setup key (20 byte)
        if ("2fa_token" not in session):
            secretToken = pyotp.random_base32() # MUST be kept secret
            session["2fa_token"] = RSA_encrypt(plaintext=secretToken)
        else:
            secretToken = RSA_decrypt(cipherData=session["2fa_token"])

        # generate a QR code for the user to scan
        totp = pyotp.totp.TOTP(s=secretToken, digits=6).provisioning_uri(name=userInfo.username, issuer_name="CourseFinity")

        # to save the image in the memory buffer
        # instead of saving the qrcode png as a file in the web server
        stream = BytesIO()

        # create a qrcode object
        qrCodeData = qrcode.make(totp, box_size=15)

        # save the qrcode image in the memory buffer
        qrCodeData.save(stream)

        # get the image from the memory buffer and encode it into base64
        qrCodeEncodedBase64 = b64encode(stream.getvalue()).decode()

        return render_template("users/user/2fa.html", form=twoFactorAuthForm, imageSrcPath=userInfo.profileImage, qrCodeEncodedBase64=qrCodeEncodedBase64, secretToken=secretToken, accType=userInfo.role)

    if (request.method == "POST" and twoFactorAuthForm.validate()):
        # POST request code below
        if ("2fa_token" not in session):
            return redirect(url_for("userBP.twoFactorAuthSetup"))

        twoFATOTP = twoFactorAuthForm.twoFATOTP.data
        secretToken = request.form.get("secretToken")
        if (secretToken is None or secretToken != RSA_decrypt(cipherData=session["2fa_token"])):
            flash("Please check your entry and try again!")
            return redirect(url_for("userBP.twoFactorAuthSetup"))

        # if the secret token and the session token is equal but
        # the secret token is not base32, then the user has tampered with the session
        # and the html 2FA secretToken hidden form value
        if (re.fullmatch(CONSTANTS.TWENTY_BYTES_2FA_REGEX, secretToken) is None):
            session.pop("2fa_token", None)
            flash("Invalid 2FA setup key, please try again!", "Danger")
            write_log_entry(
                logMessage=f"User: {userID}, IP address: {get_remote_address()}, 2FA token matches session token but is not base32.",
                severity="ALERT"
            )
            return redirect(url_for("userBP.twoFactorAuthSetup"))

        # check if the TOTP is valid
        if (pyotp.TOTP(secretToken).verify(twoFATOTP)):
            # update the user's 2FA status to True
            sql_operation(table="2fa_token", mode="add_token", userID=userInfo.uid, token=secretToken)
            flash(Markup("2FA has been <span class='text-success'>enabled</span> successfully!<br>You will now be prompted to key in your time-based OTP whenever you login now!"), "2FA has been enabled!")
            return redirect(url_for("userBP.userProfile"))
        else:
            flash("Please check your entry and try again!")
            return redirect(url_for("userBP.twoFactorAuthSetup"))

    # post request but form inputs are not valid
    return redirect(url_for("userBP.twoFactorAuthSetup"))

@userBP.route("/2fa/backup-codes", methods=["GET", "POST"])
def showBackupCodes():
    userID = session["user"]
    # check if user logged in via Google OAuth2
    try:
        loginViaGoogle = sql_operation(table="user", mode="check_if_using_google_oauth2", userID=userID)
    except (UserDoesNotExist):
        abort(403) # if for whatever reason, a user does not exist, abort

    if (loginViaGoogle):
        # if so, redirect to user profile as the authentication security is handled by Google themselves
        return redirect(url_for("userBP.userProfile"))

    if (not sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userID)):
        return redirect(url_for("userBP.twoFactorAuthSetup"))

    backUpCodes = []
    if (request.method == "POST"):
        action = request.form.get("action", default=None, type=str)
        if (action != "generate_codes"):
            return redirect(url_for("userBP.showBackupCodes"))

        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Please verify that you are not a bot.", "Sorry!")
            return redirect(url_for("userBP.showBackupCodes"))

        try:
            recaptchaResponse = create_assessment(
                recaptchaToken=recaptchaToken, recaptchaAction="generate_backup_codes"
            )
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Please verify that you are not a bot!", "Sorry!")
            return redirect(url_for("userBP.showBackupCodes"))

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Please verify that you are not a bot!", "Sorry!")
            return redirect(url_for("userBP.showBackupCodes"))

        backUpCodes = sql_operation(table="2fa_token", mode="generate_codes", userID=userID)

    if (request.method == "GET"):
        backUpCodes = sql_operation(table="2fa_token", mode="get_backup_codes", userID=userID)
        if (len(backUpCodes) < 1):
            backUpCodes = sql_operation(table="2fa_token", mode="generate_codes", userID=userID)

    userID = session["user"]
    userInfo = get_image_path(userID, returnUserInfo=True)
    return render_template("users/user/backup_codes.html", backupCodes=backUpCodes, imageSrcPath=userInfo.profileImage, accType=userInfo.role)

@userBP.post("/disable-2fa")
def disableTwoFactorAuth():
    userID = session["user"]
    # check if user logged in via Google OAuth2
    try:
        loginViaGoogle = sql_operation(table="user", mode="check_if_using_google_oauth2", userID=userID)
    except (UserDoesNotExist):
        abort(403) # if for whatever reason, a user does not exist, abort

    if (loginViaGoogle):
        # if so, redirect to user profile as the authentication security is handled by Google themselves
        return redirect(url_for("userBP.userProfile"))

    if (sql_operation(table="2fa_token", mode="check_if_user_has_2fa", userID=userID)):
        sql_operation(table="2fa_token", mode="delete_token", userID=userID)
        flash(Markup("Two factor authentication has been <span class='text-danger'>disabled</span>!<br>You will no longer be prompted to enter your 2FA time-based OTP."), "2FA Disabled!")
    else:
        flash("You do not have 2FA enabled!", "2FA Is NOT Enabled!")

    return redirect(url_for("userBP.userProfile"))

@userBP.route("/change-email", methods=["GET","POST"])
def updateEmail():
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
            return render_template("users/user/change_email.html", form=create_update_email_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)
        else:
            print(f"old email:{oldEmail}, new email:{updatedEmail}")
            flash(
                "Your email has been successfully changed. However, a link has been sent to your new email to verify your new email!",
                "Account Details Updated!"
            )
            return redirect(url_for("userBP.userProfile"))
    else:
        return render_template("users/user/change_email.html", form=create_update_email_form, imageSrcPath=userInfo.profileImage, accType=userInfo.role)

@userBP.post("/change-account-type")
def changeAccountType():
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

@userBP.post("/delete-profile-picture")
def deletePic():
    userInfo = get_image_path(session["user"], returnUserInfo=True)
    if ("https://storage.googleapis.com/coursefinity" in userInfo.profileImage):
        sql_operation(table="user", mode="delete_profile_picture", userID=userInfo.uid)
        flash("Your profile picture has been successfully deleted.", "Profile Picture Deleted!")
    return redirect(url_for("userBP.userProfile"))

@csrf.exempt
@userBP.post("/upload-profile-picture")
def uploadPic():
    userID = session["user"]
    if ("profilePic" not in request.files):
        print("No File Sent")
        return redirect(url_for("userBP.userProfile"))

    file = request.files["profilePic"]
    filename = secure_filename(file.filename)
    if (filename == "" or not accepted_file_extension(filename=filename, typeOfFile="image")):
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

#TODO: Doing dropzone, just realised we dont download the file locally. So need ask if i shld store file locally first check then delete, then upload to bucket. Code already in place for it, just need approval.
# TODO : If approved test if working, if not delete
# TODO: Looks like upload file from path already uses CRC32C checksum, clarify if need to do here also
# @csrf.exempt
# @userBP.post("/upload-profile-picture")
# def uploadPic():
#     if ("image_saving" not in session):
#         imageID = generate_id(sixteenBytesTimes=2)
#         session["image_saving"] = [imageID, None] # Saving started; interruption = restart from scratch
#     else:
#         imageID = session["image_saving"][0]
#         try:
#             resp = request.json
#             session["image_saving"] = [imageID, resp["hash"]]
#         except Exception as e:
#             # print(e)
#             # write_log_entry(logMessage=f"Error in videoUpload: {e}", severity="WARNING")
#             # return make_response("Unexpected error", 500)
#             pass
#         #TODO : Find a way to check if this was the file currently being saved or not

#     userID = session["user"]
#     if ("profilePic" not in request.files):
#         print("No File Sent")
#         return redirect(url_for("userBP.userProfile"))
        
#     file = request.files["profilePic"]
#     filename = secure_filename(file.filename)
#     if (filename == "" or not accepted_file_extension(filename=filename, typeOfFile="image")):
#         flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Profile Image!")
#         return redirect(url_for("userBP.userProfile"))
#     totalChunks = int(request.form["dztotalchunkcount"])
#     currentChunk = int(request.form['dzchunkindex'])
#     print("Total file size:", int(request.form["dztotalfilesize"]))

#     filePath = Path(imageID + Path(filename).suffix)
#     imageData = BytesIO(file.read())
#     absFilePath = current_app.config["USER_IMAGE_VOLDER"].joinpath(filePath)

#     try:
#         with open(absFilePath, "ab") as imageData: # ab flag for opening a file for appending data in binary format
#             imageData.seek(int(request.form["dzchunkbyteoffset"]))
#             print("dzchunkbyteoffset:", int(request.form["dzchunkbyteoffset"]))
#             imageData.write(file.stream.read())
#     except (OSError):
#         print("Could not write to file")
#         return make_response("Error writing to file", 500)
#     except:
#         print("Unexpected error.")
#         return make_response("Unexpected error", 500)
        
#     if (currentChunk + 1 == totalChunks):
#         # This was the last chunk, the file should be complete and the size we expect
#         if (absFilePath.stat().st_size != int(request.form["dztotalfilesize"])):
#             print(f"File {filename} was completed, but there is a size mismatch. Received {absFilePath.stat().st_size} but had expected {request.form['dztotalfilesize']}")
#             # remove corrupted image
#             absFilePath.unlink(missing_ok=True) # missing_ok argument is set to True as the file might not exist (>= Python 3.8)
#             #pop to prevent further error
#             session.pop("image_saving", None)
#             return make_response("Uploaded image is corrupted! Please try again!", 500)
#         else:
#             print(f"File {filename} has been uploaded successfully")

#             # COMPARISON OF HASH
#             hashNum = session["image_saving"][1]
#             if (hashNum):
#                 with open(absFilePath, "rb") as f:
#                     fileHash = hashlib.sha512(f.read()).hexdigest()

#                 if (fileHash != hashNum):
#                     print("File Hash is incorrect")
#                     absFilePath.unlink(missing_ok=True)
#                     session.pop("image_saving", None)
#                     return make_response("Uploaded image is corrupted! Please try again!", 500)

#                 try:
#                     imageUrlToStore = compress_and_resize_image(
#                         imageData=imageData, imagePath=filePath, dimensions=(500, 500), 
#                         folderPath=f"user-profiles"
#                     )
#                 except (InvalidProfilePictureError):
#                     flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Profile Image!")
#                     return redirect(url_for("userBP.userProfile"))
#                 except (UploadFailedError):
#                     flash(Markup("Sorry, there was an error uploading your profile picture...<br>Please try again later!"), "Failed to Upload Profile Image!")
#                     return redirect(url_for("userBP.userProfile"))

#     absFilePath.unlink(missing_ok=True)
#     session.pop("image_saving", None)
#     sql_operation(table="user", mode="change_profile_picture", userID=userID, profileImagePath=imageUrlToStore)
#     flash(Markup("Your profile picture has been successfully uploaded.<br>If your profile picture has not changed on your end, please wait or clear your browser cache to see the changes."), "Profile Picture Uploaded!")
#     return redirect(url_for("userBP.userProfile"))


@userBP.route("/course-review/<string:courseID>", methods=["GET","POST"]) #writing of review
def courseReview(courseID:str):
    reviewForm = CreateReview(request.form)
    # get course data 
    course=sql_operation(table="course", mode="get_course_data", courseID=courseID)

    # get user data
    print("user is logged in")
    userID=session["user"]
    userInfo = get_image_path(session["user"], returnUserInfo=True)
    print(userInfo)
    purchasedCourseIDs = userInfo.purchasedCourses
    print(purchasedCourseIDs)

    for purchases in purchasedCourseIDs:
        if (purchases == courseID):
            purchased = True
            break

    if (not purchased):
        print("user has not purchased this course")
        abort(404)
    print("user has purchased this course")         
    review = False

    reviews = sql_operation(table="review", mode="retrieve_all", courseID=courseID)
    for review in reviews:
        # print(review) # commented it out to prevent massive prints
        if (review[0] == userID and review[1] == courseID):
            review = True
            break

    if (review):
        print("user has already reviewed this course")
        abort(404)
    print("user has not reviewed this course")

    if (request.method == "POST" and reviewForm.validate()):
        print("post request")
        print("form validated")
        review = reviewForm.reviewDescription.data
        print("review:",review)
        rating= request.form.get("rate")
        print("rating:",rating)
        sql_operation(
            table="review", mode="add_review", courseID=courseID, userID=userID,
            courseReview=review, courseRating=rating
        )
        print("review updated")
        flash("Your review has been successfully added.", "Review Added!")
        #redirect back to coursepage
        return redirect(url_for("generalBP.coursePage", courseID=courseID))
    else:
        return render_template("users/user/purchase_review.html", form=reviewForm, course=course, userID=userID, imageSrcPath=userInfo.profileImage)

@userBP.route("/purchase-view/<string:courseID>")
def purchaseView(courseID:str):
    # TODO: Make the argument based on the purchaseID instead of courseID
    print(courseID)
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    print(courses)
    #courseName = courses[0][1]
    if (not courses): #raise 404 error
        abort(404)

    # TODO: Could have used Course.py's class instead of
    # TODO: manually retrieving the data from the tuple
    # TODO: Prevent iframes from being loaded in the course description
    #create variable to store these values
    courseDescription = Markup(
        markdown.markdown(
            html.escape(courses.courseDescription),
            extensions=[AnchorTagExtension()], 
        )
    )

    courseVideoPath = None
    teacherRecords = get_image_path(courses.teacherID, returnUserInfo=True)
    print(teacherRecords)

    accType = imageSrcPath = None
    userPurchasedCourses = {}
    userInfo = get_image_path(session["user"], returnUserInfo=True)
    userPurchasedCourses = userInfo.uid
    accType = userInfo.role
    imageSrcPath = userInfo.profileImage
    videoPath = validate_course_video_path(courseID=courseID, returnUrl=True)

    return render_template("users/user/purchase_view.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, teacherName=teacherRecords.username, teacherProfilePath=teacherRecords.profileImage, courseDescription=courseDescription, courseVideoPath=courseVideoPath, accType=accType, courses=courses, videoPath=videoPath)

@userBP.post("/add_to_cart/<string:courseID>")
def addToCart(courseID:str):
    sql_operation(table="user", mode="add_to_cart", userID=session["user"], courseID=courseID)
    return redirect(url_for("userBP.shoppingCart"))

@userBP.route("/shopping-cart", methods=["GET", "POST"])
def shoppingCart():
    print(str(session))
    userID = session["user"]
    if request.method == "POST":
        # Remove item from cart
        courseID = request.form.get("courseID")
        sql_operation(table="user", mode="remove_from_cart", userID=userID, courseID=courseID)

        return redirect(url_for("userBP.shoppingCart"))

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
        return render_template("users/user/shopping_cart.html", courseList=courseList, subtotal=f"{subtotal:,.2f}", imageSrcPath=userInfo.profileImage, accType=userInfo.role)

@userBP.route("/checkout", methods = ["GET", "POST"])
def checkout():
    userID = session["user"]

    cartCourseIDs = sql_operation(table='user', mode = 'get_user_cart', userID = userID)
    if cartCourseIDs == []: # Take that, Postman users!
        return redirect(url_for("userBP.shoppingCart"))
    email = sql_operation(table = 'user', mode = 'get_user_data', userID = userID).email
    print(cartCourseIDs)
    print(email)

    try:
        checkout_session = stripe_checkout(userID = userID, cartCourseIDs = cartCourseIDs, email = email)
    except Exception as error:
        print(str(error))
        return redirect(url_for('userBP.addToCart', courseID=cartCourseIDs[0]))

    print(checkout_session)
    print(type(checkout_session))

    return redirect(checkout_session.url, code = 303) # Stripe says use 303, we shall stick to 303

@userBP.route("/purchase/<string:jwtToken>")
def purchase(jwtToken:str):
    data = EC_verify(jwtToken, getData = True)

    if not data.get("verified"):
        abort(400)

    tokenID = data["data"].get("token_id")
    if (tokenID is None):
        abort(404)

    if not sql_operation(table="limited_use_jwt", mode="jwt_is_valid", tokenID=tokenID):
        abort(400)

    sql_operation(table="limited_use_jwt", mode="decrement_limit_after_use", tokenID=tokenID)

    payload = data['data']['payload']
    tokenCartCourseIDs = payload.get('cartCourseIDs') # The courses paid for,
    tokenUserID = payload.get('userID')               # To the person who generated the payment.
    paymentID = payload.get('paymentID')
    
    send_checkout_receipt(paymentID)
    sql_operation(table="user", mode="purchase_courses", userID = tokenUserID, cartCourseIDs = tokenCartCourseIDs)

    return redirect(url_for("userBP.purchaseHistory"))

@userBP.route("/purchase-history")
def purchaseHistory():
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

    return render_template("users/user/purchase_history.html", courseList=courseList, imageSrcPath=userInfo.profileImage, accType=userInfo.role)