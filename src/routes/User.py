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
        if ("https" not in imageSrcPath):
            fileName = imageSrcPath.rsplit("/", 1)[-1]
            Path(current_app.config["PROFILE_UPLOAD_PATH"]).joinpath(fileName).unlink(missing_ok=True)
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
        filename = file.filename
        if (filename.strip() == ""):
            abort(500)

        if (not accepted_image_extension(filename)):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Profile Image!")
            return redirect(url_for("userBP.userProfile"))

        filename = f"{userID}.webp"
        print(f"This is the filename for the inputted file : {filename}")

        filePath = current_app.config["PROFILE_UPLOAD_PATH"].joinpath(filename)
        print(f"This is the filepath for the inputted file: {filePath}")

        imageData = BytesIO(file.read())
        compress_and_resize_image(imageData=imageData, imagePath=filePath, dimensions=(500, 500))

        imageUrlToStore = url_for("static", filename=f"images/user/{filename}")
        sql_operation(table="user", mode="change_profile_picture", userID=userID, profileImagePath=imageUrlToStore)

        return redirect(url_for("userBP.userProfile"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/video-upload", methods=["GET", "POST"])
def videoUpload():
    if ("user" in session):
        courseID = generate_id()
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        if (userInfo[1] != "Teacher"):
            abort(500)

        if (request.method == "POST"):
            if (request.files["courseVideo"].filename == ""):
                flash("Please Upload a Video", "File Upload Error!")
                return redirect(url_for("userBP.videoUpload"))
            file = request.files.get("courseVideo")
            filename = secure_filename(file.filename)

            print(f"This is the filename for the inputted file : {filename}")

            filePath = Path(current_app.config["COURSE_VIDEO_FOLDER"]).joinpath(courseID)
            print(f"This is the folder for the inputted file: {filePath}")
            filePath.mkdir(parents=True, exist_ok=True)

            filePathToStore  = url_for("static", filename=f"course_videos/{courseID}/{filename}")
            file.save(Path(filePath).joinpath(filename))

            session["course-data"] = (courseID, filePathToStore)
            return redirect(url_for("userBP.createCourse"))
        else:
            return render_template("users/teacher/video_upload.html",imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("guestBP.login"))


#TODO: Hash Video data, implement dropzone to encrpyt video data
@userBP.route("/create-course", methods=["GET","POST"])
def createCourse():
    if ("user" in session):
        if ("course-data" in session):
            courseData = session["course-data"]
            imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
            if (userInfo[1] != "Teacher"):
                abort(500)

            courseForm = CreateCourse(request.form)
            if (request.method == "POST"):
                courseTitle = courseForm.courseTitle.data
                courseDescription = courseForm.courseDescription.data
                courseTagInput = request.form.get("courseTag")
                coursePrice = float(courseForm.coursePrice.data)

                file = request.files.get("courseThumbnail")
                filename = file.filename
                if (filename.strip() == ""):
                    abort(500)

                filename = f"{courseData[0]}.webp"
                print(f"This is the filename for the inputted file : {filename}")

                filePath = Path(current_app.config["THUMBNAIL_UPLOAD_PATH"]).joinpath(courseData[0])
                print(f"This is the Directory for the inputted file: {filePath}")
                filePath.mkdir(parents=True, exist_ok=True)

                imageData = BytesIO(file.read())
                compress_and_resize_image(imageData=imageData, imagePath=Path(filePath).joinpath(filename), dimensions=(1920, 1080))

                imageUrlToStore = (f"{courseData[0]}/{filename}")

                # print(f"This is the filename for the inputted file : {filename}")
                # filePath = Path(current_app.config["THUMBNAIL_UPLOAD_PATH"]).joinpath(filename)
                # print(f"This is the filePath for the inputted file: {filePath}")
                # file.save(filePath)

                sql_operation(table="course", mode="insert",courseID=courseData[0], teacherID=userInfo[0], courseName=courseTitle, courseDescription=courseDescription, courseImagePath=imageUrlToStore, courseCategory=courseTagInput, coursePrice=coursePrice, videoPath=courseData[1])
                stripe_product_create(courseID=courseData[0], courseName=courseTitle, courseDescription=courseDescription, coursePrice=coursePrice, courseImagePath=imageUrlToStore)


                session.pop("course-data")
                flash("Course Created", "Course Created Successfully!")
                return redirect(url_for("userBP.userProfile"))
            else:
                return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1], courseID=courseData[0], videoPath=courseData[1])
        else:
            flash("No Video Uploaded", "File Upload")
            return redirect(url_for("userBP.videoUpload"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/course-video-list")
def courseList():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        courseList = sql_operation(table="course", mode="get_all_courses", teacherID=userInfo[0])

        #TODO: Test if works, currently not sure cause idk which vimeo module to use
        page = request.args.get("p", default=1, type=int)
        eachPageResults = []
        dictOfResults = {}
        pageNum = 1

        if (len(courseList) != 0):
            for eachResult in courseList:
                if (len(eachPageResults)!=10):
                    eachPageResults.append(eachResult)
                    dictOfResults[pageNum] = eachPageResults
                else:
                    dictOfResults[pageNum] = eachPageResults
                    eachPageResults = [eachResult]
                    pageNum += 1

            maxPage = max(list(dictOfResults))
            if (page > maxPage):
                abort(404)

            return render_template("users/teacher/course_list.html", imageSrcPath=imageSrcPath, courseListLen=len(courseList), currentPage=page, courseList=dictOfResults[page], lenOfDict=dictOfResults, maxPage=maxPage,accType=userInfo[1])

        return render_template("users/teacher/course_list.html", imageSrcPath=imageSrcPath, courseListLen=len(courseList), accType=userInfo[1])

    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/delete-course-video", methods=["GET", "POST"])
def courseDelete():
    if ("user" in session):
        courseID = request.args.get("cid", default="test", type=str)
        sql_operation(table="course", mode="delete", courseID=courseID)
        print("Course Deleted")
        return redirect(url_for("userBP.courseList"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/course-video-edit", methods=["GET", "POST"])
def courseUpdate():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        #TODO: Make the update video details form
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/course-review/<string:courseID>") #writing of review
def courseReview(courseID:str):
    accType = imageSrcPath = None
    userPurchasedCourses = {}
    reviewDate = datetime.datetime.now().strftime("%Y-%m-%d")
    courses = sql_operation(table="", mode="", courseID=courseID)

    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        userPurchasedCourses = sql_operation(table="user", mode="get_user_purchases", userID=session["user"])
        accType = userInfo[1]

    return render_template("users/general/course_page_review.html",
        imageSrcPath=imageSrcPath, userPurchasedCourses=userPurchasedCourses, courseID=courseID, accType=accType)

@userBP.route("/purchase-view/<string:courseID>")
def purchaseView(courseID:str):
    # TODO: Make the argument based on the purchaseID instead of courseID
    print(courseID)
    courses = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    #courseName = courses[0][1]
    if courses == False: #raise 404 error
        abort(404)

    # TODO: Could have used Course.py's class instead of
    # TODO: manually retrieving the data from the tuple
    #create variable to store these values
    teacherID = courses[1]
    courseName = courses[2]
    courseDescription = Markup(
        markdown.markdown(
            courses[3],
            extensions=[AnchorTagPreExtension(), AnchorTagPostExtension()]
        )
    )
    course_image_path = courses[4]
    coursePrice = courses[5]
    courseCategory = courses[6]
    courseRating = courses[7]
    courseRatingCount = courses[8]
    courseDate = courses[9]
    courseVideoPath = courses[10]

    # videoID = vimeo_upload(r"C:\Users\wrenp\Downloads\the_fuck.mp4", r"C:\Users\wrenp\Downloads\Emote\DoremyToot_Optimised.png", 'Imperishable Night', 'This is a test video.')
    videoData = get_vimeo_video(726279222)
    courseVideoPath = loads(videoData.text)["html"]
    print(loads(videoData.text)["html"])

    print("course",courses[1])

    teacherProfilePath = get_image_path(teacherID)
    teacherRecords = sql_operation(table="user", mode="get_user_data", userID=teacherID)
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
        , courseID=courseID, courseName=courseName, courseDescription=courseDescription, coursePrice=coursePrice, courseCategory=courseCategory, \
        courseRating=courseRating, courseRatingCount=courseRatingCount, courseDate=courseDate, courseVideoPath=courseVideoPath, accType=accType,\
        course_image_path=course_image_path)

@userBP.post("/add_to_cart/<string:courseID>")
def addToCart(courseID:str):
    if ("user" in session):
        sql_operation(table="user", mode="add_to_cart", userID=session["user"], courseID=courseID)
        return redirect(url_for("userBP.cart"))
    else:
        return redirect(url_for("guestBP.login"))

@userBP.route("/shopping_cart", methods=["GET", "POST"])
def cart():
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

@userBP.route("/purchase_history")
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
            if course != False:
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

        return render_template("users/loggedin/purchase_history.html", courseList=courseList, imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for('guestBP.login'))
