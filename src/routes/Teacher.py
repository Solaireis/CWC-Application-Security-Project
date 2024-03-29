"""
Routes for logged in Teachers
"""
# import third party libraries
from werkzeug.utils import secure_filename

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, current_app

# import local python libraries
from python_files.functions.SQLFunctions import *
from python_files.functions.NormalFunctions import *
from python_files.functions.StripeFunctions import *
from python_files.functions.VideoFunctions import *
from python_files.classes.Forms import *
from python_files.classes.Course import get_readable_category
from python_files.classes.MarkdownExtensions import AnchorTagExtension

# import python standard libraries
from pathlib import Path
from io import BytesIO
import markdown,html

teacherBP = Blueprint("teacherBP", __name__, static_folder="static", template_folder="template")

@teacherBP.route("/course-list")
def courseList():
    page = request.args.get("p", default=1, type=int)
    if (page < 1):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].NEGATIVE_PAGE_NUM_REGEX, "p=1", request.url, count=1)
        )

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    courseList, maxPage = sql_operation(table="course", mode="get_all_courses_by_teacher", teacherID=userInfo.uid, pageNum=page)

    if (page > maxPage):
        return redirect(url_for("teacherBP.courseList") + f"?p={maxPage}")

    paginationArr = []
    if (len(courseList) != 0) :
        # Compute the buttons needed for pagination
        paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)

    return render_template("users/general/course_list.html", imageSrcPath=userInfo.profileImage, courseListLen=len(courseList), accType=userInfo.role, currentPage=page, maxPage=maxPage, courseList=courseList, isOwnself=True, paginationArr=paginationArr)

@teacherBP.route("/draft-course-list")
def draftCourseList():
    #TODO Fix this to fit, add button in course list html to redirect to draft page, if user has drafted courses
    page = request.args.get("p", default=1, type=int)
    if (page < 1):
        return redirect(
            re.sub(current_app.config["CONSTANTS"].NEGATIVE_PAGE_NUM_REGEX, "p=1", request.url, count=1)
        )

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    courseList, maxPage = sql_operation(table="course", mode="get_all_draft_courses", teacherID=userInfo.uid, pageNum=page)
    videoStatusList = tuple(check_video(course.videoPath)["status"] for course in courseList)

    if (page > maxPage):
        return redirect(url_for("teacherBP.draftCourseList") + f"?p={maxPage}")

    paginationArr = []
    if (len(courseList) != 0) :
        paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)

    return render_template(
        "users/teacher/draft_course_list.html", imageSrcPath=userInfo.profileImage, courseListLen=len(courseList),
        accType=userInfo.role, currentPage=page, maxPage=maxPage, courseList=courseList,
        paginationArr=paginationArr, videoStatusList=videoStatusList
    )

""" Start of Course Creation API Calls """

@teacherBP.route("/client-payload/<string:teacherID>")
def clientPayload(teacherID):
    # Manipulating other userIDs?
    if session["user"] != teacherID:
        abort(401)

    clientPayload = sql_operation(table="course", mode="insert_draft", teacherID=teacherID)

    if clientPayload is None:
        abort(400) #TODO Test the error code and see what could be redirected instead of 404 for better user experience

    return clientPayload

@teacherBP.route("/video-uploaded/<string:teacherID>")
def uploadSuccess(teacherID):
    # Manipulating other userIDs?
    if session["user"] != teacherID:
        abort(401)
    sql_operation(table="course", mode="complete_draft", teacherID=teacherID)
    return redirect(url_for("teacherBP.draftCourseList"))

""" End of Course Creation API Calls """

""" Start Of Course Creation """

@teacherBP.route("/upload-video", methods=["GET", "POST"])
def videoUpload():
    userInfo = get_image_path(session["user"], returnUserInfo=True)
    payloadUrl = url_for('teacherBP.clientPayload', teacherID = userInfo.uid)
    return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role, payloadUrl=payloadUrl)

@teacherBP.route("/create-course/<string:courseID>", methods=["GET","POST"])
def createCourse(courseID:str):
    courseTuple = sql_operation(table="course", mode="get_draft_course_data", courseID=courseID)
    if (not courseTuple):
        flash("Course Already Created / Draft Does not exist!", "Course Creation error")
        return redirect(url_for("teacherBP.courseList"))

    videoPath = courseTuple[2]
    userInfo = get_image_path(session["user"], returnUserInfo=True)

    # Check if course exists
    videoData = check_video(videoPath)
    if videoData is None: # video doesn't exist
        abort(404) #TODO Test the error code and see what could be redirected instead of 404 for better user experience
    elif videoData["status"] != "ready": # Video is in processing/error
        abort(400) #TODO Test the error code and see what could be redirected instead of 404 for better user experience

    videoData = get_video(videoPath)

    if (userInfo.role != "Teacher"):
        abort(404) #TODO Test the error code and see what could be redirected instead of 404 for better user experience

    courseForm = CreateCourse(request.form)
    if (request.method == "POST" and courseForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!", "Sorry!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="create_course")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!", "Sorry!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!", "Sorry!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

        courseTitle = courseForm.courseTitle.data
        courseDescription = courseForm.courseDescription.data
        courseTagInput = request.form.get("courseTag")
        coursePrice = float(courseForm.coursePrice.data)

        if (get_readable_category(courseTagInput) == "Unknown Category"):
            flash("Please select a valid category for your course details!", "Invalid Course Category")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

        file = request.files.get("courseThumbnail")
        filename = secure_filename(file.filename)
        if (filename == "" or not accepted_file_extension(filename=filename, typeOfFile="image")):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

        filePath = Path(generate_id(sixteenBytesTimes=2) + Path(filename).suffix)
        imageData = BytesIO(file.read())
        try:
            imageUrlToStore = compress_and_resize_image(
                imageData=imageData, imagePath=filePath, dimensions=(1920, 1080),
                folderPath=f"course-thumbnails"
            )
            if update_video_thumbnail(videoPath, imageUrlToStore) is None:
                flash("Image is invalid and cannot be parsed.", "Failed to Upload Course Thumbnail!")
                return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)
        except (InvalidProfilePictureError):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)
        except (UploadFailedError):
            flash(Markup("Sorry, there was an error uploading your course thumbnail...<br>Please try again later!"), "Failed to Upload Course Thumbnail!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

        sql_operation(
            table="course",
            mode="insert",
            courseID=courseID,
            teacherID=userInfo.uid,
            courseName=courseTitle,
            courseDescription=courseDescription,
            courseImagePath=imageUrlToStore,
            courseCategory=courseTagInput,
            coursePrice=coursePrice,
            videoPath=videoPath
        )
        stripe_product_create(
            courseID=courseID,
            courseName=courseTitle,
            courseDescription=courseDescription,
            coursePrice=coursePrice,
            courseImagePath=imageUrlToStore
        )
        sql_operation(table="course", mode="delete_from_draft", courseID=courseID)

        flash("Course Created", "Successful Course Created!")
        return redirect(url_for("userBP.courseList"))
    else:
        return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoData=videoData)

""" End Of Course Creation """

""" Start Of Course Management """

@teacherBP.route("/delete-course", methods=["GET", "POST"])
def courseDelete():
    courseID = request.args.get("cid", default="test", type=str)
    courseFound = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courseFound or not courseFound.status):
        abort(404)

    sql_operation(table="course", mode="delete", courseID=courseID)
    print("Course Deleted")
    return redirect(url_for("teacherBP.courseList"))

@teacherBP.route("/delete-draft-course", methods=["GET", "POST"])
def draftCourseDelete():
    courseID = request.args.get("cid", default="test", type=str)
    courseFound = sql_operation(table="course", mode="get_draft_course_data", courseID=courseID)
    if (not courseFound):
        abort(404) #TODO Test the error code and see what could be redirected instead of 404 for better user experience

    delete_video(courseFound[2])
    sql_operation(table="course", mode="delete_from_draft", courseID=courseID)
    print("Draft Course Deleted")
    return redirect(url_for("teacherBP.draftCourseList"))

@teacherBP.route("/edit-course", methods=["GET", "POST"])
def courseUpdate():
    courseID = request.args.get("cid", default="test", type=str)
    courseFound = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courseFound or not courseFound.status):
        abort(404)

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    courseForm = CreateCourseEdit(request.form)
    updated = ""
    if (request.method == "POST"):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="edit_course")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.7)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Verification error with reCAPTCHA, please try again!", "Danger")
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)

        if (courseForm.courseTitle.data):
            if (courseForm.courseTitle.data != courseFound.courseName):
                sql_operation(table="course", mode="update_course_title", courseID=courseID, courseTitle=courseForm.courseTitle.data)
                stripe_product_update(courseID=courseID, courseName=courseForm.courseTitle.data)
                updated += "Course Title, "

        if (request.form.get("courseDescription")):
            if (request.form.get("courseDescription") != courseFound.courseDescription):
                sql_operation(table="course", mode="update_course_description", courseID=courseID, courseDescription=courseForm.courseDescription.data)
                stripe_product_update(courseID=courseID, courseDescription=courseForm.courseDescription.data)
                updated += "Course Description, "

        if (courseForm.coursePrice.data):
            if (float(courseForm.coursePrice.data) != float(courseFound.coursePrice)):
                sql_operation(table="course", mode="update_course_price", courseID=courseID, coursePrice=courseForm.coursePrice.data)
                stripe_product_update(courseID=courseID, coursePrice=courseForm.coursePrice.data)
                updated += "Course Price, "

        courseTagInput = request.form.get("courseTag")
        if (courseTagInput != courseFound.courseCategory):
            sql_operation(table="course", mode="update_course_category", courseID=courseID, courseCategory=courseTagInput)
            updated += "Course Tag, "

        file = request.files.get("courseThumbnail")
        filename = secure_filename(file.filename)
        if (filename != ""):
            filePath = Path(generate_id(sixteenBytesTimes=2) + Path(filename).suffix)
            imageData = BytesIO(file.read())
            try:
                imageUrlToStore = compress_and_resize_image(
                    imageData=imageData, imagePath=filePath, dimensions=(1920, 1080),
                    folderPath=f"course-thumbnails"
                )
            except (InvalidProfilePictureError):
                flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
                return redirect("teacherBP.courseList")
            except (UploadFailedError):
                flash(Markup("Sorry, there was an error uploading your profile picture...<br>Please try again later!"), "Failed to Upload Course Thumbnail!")
                return redirect("teacherBP.courseList")

            sql_operation(table="course", mode="update_course_thumbnail", courseID=courseID, courseImagePath=imageUrlToStore)
            stripe_product_update(courseID=courseID, courseImagePath=imageUrlToStore)
            update_video_thumbnail(courseFound.videoPath, imageUrlToStore)
            updated += "Course Thumbnail, "

        if (len(updated) > 0):
            flash(f"Fields Updated : {updated}", "Successful Update")
        return redirect(url_for("teacherBP.courseList"))

    courseDescription = Markup(
        markdown.markdown(
            html.escape(courseFound.courseDescription),
            extensions=[AnchorTagExtension()],
        )
    )

    return render_template(
        "users/teacher/course_video_edit.html",
        form=courseForm, imageSrcPath=userInfo.profileImage,
        accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName,
        courseDescription=courseDescription, courseDescription2 = courseFound.courseDescription, coursePrice=courseFound.coursePrice,
        courseTag=courseFound.courseCategory, videoData=get_video(courseFound.videoPath)
    )

""" End Of Course Management """