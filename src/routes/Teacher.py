"""
Routes for logged in Teachers
"""
# import third party libraries
from werkzeug.utils import secure_filename

# import flask libraries (Third-party libraries)
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint, current_app, make_response

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
import platform, hashlib, shutil

teacherBP = Blueprint("teacherBP", __name__, static_folder="static", template_folder="template")

@teacherBP.route("/course-video-list")
def courseList():
    userInfo = get_image_path(session["user"], returnUserInfo=True)
    page = request.args.get("p", default=1, type=int)
    maxPage, paginationArr = 0, []
    courseList = sql_operation(table="course", mode="get_all_courses_by_teacher", teacherID=userInfo.uid, pageNum=page)
    try:
        if (not courseList[0]):
            return redirect(url_for("teacherBP.courseList") + f"?p={courseList[1]}")
        if (len(courseList) != 0) :
            courseList, maxPage = courseList[0], courseList[1]
            # Compute the buttons needed for pagination
            paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)
    except:
        courseList = []

    return render_template("users/general/course_list.html", imageSrcPath=userInfo.profileImage, courseListLen=len(courseList), accType=userInfo.role, currentPage=page, maxPage=maxPage, courseList=courseList, isOwnself=True, paginationArr=paginationArr)

@teacherBP.route("/draft-course-video-list")
def draftCourseList():
    #TODO Fix this to fit, add button in course list html to redirect to draft page, if user has drafted courses
    userInfo = get_image_path(session["user"], returnUserInfo=True)
    page = request.args.get("p", default=1, type=int)
    maxPage, paginationArr = 0, []
    courseList = sql_operation(table="course", mode="get_all_draft_courses", teacherID=userInfo.uid, pageNum=page)
    try:
        if (not courseList[0]):
            return redirect(url_for("teacherBP.draftCourseList") + f"?p={courseList[1]}")
        if (len(courseList) != 0) :
            courseList, maxPage = courseList[0], courseList[1]
            # Compute the buttons needed for pagination
            paginationArr = get_pagination_arr(pageNum=page, maxPage=maxPage)
    except:
        courseList = []

    return render_template("users/teacher/draft_course_list.html", imageSrcPath=userInfo.profileImage, courseListLen=len(courseList), accType=userInfo.role, currentPage=page, maxPage=maxPage, courseList=courseList,paginationArr=paginationArr)

""" Start Of Course Creation """

# @csrf.exempt
# @teacherBP.route("/upload-video", methods=["GET", "POST"])
# def videoUpload():
#     if ("user" in session): #TODO: DELETE IF USER IN SESSION IF UNCOMMENTED
#         userInfo = get_image_path(session["user"], returnUserInfo=True)
#         if (userInfo.role != "Teacher"):
#             abort(404)

#         if (request.method == "POST"):
#             # recaptchaToken = request.form.get("g-recaptcha-response")
#             # if (recaptchaToken is None):
#             #     flash("Please verify that you are not a bot!", "Danger")
#             #     return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)

#             # try:
#             #     recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="upload")
#             # except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
#             #     flash("Please verify that you are not a bot!", "Danger")
#             #     return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)

#             # if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.75)):
#             #     # if the score is not within the acceptable threshold
#             #     # then the user is likely a bot
#             #     # hence, we will flash an error message
#             #     flash("Please check the reCAPTCHA box and try again.", "Danger")
#             #     return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)
#             print(request.files["videoUpload"])
#             if (request.files["courseVideo"].filename == ""):
#                 flash("Please Upload a Video", "File Upload Error!")
#                 return redirect(url_for("teacherBP.videoUpload"))

#             file = request.files.get("courseVideo")
#             filename = secure_filename(file.filename)

#             print(f"This is the ORIGINAL filename for the inputted file : {filename}")

#             courseID = generate_id()
#             filePath = Path(current_app.config["COURSE_VIDEO_FOLDER"]).joinpath(courseID)
#             print(f"This is the folder for the inputted file: {filePath}")
#             filePath.mkdir(parents=True, exist_ok=True)

#             filePathToStore  = url_for("static", filename=f"course_videos/{courseID}/{filename}")
#             file.save(Path(filePath).joinpath(filename))

#             """
#             Create a row inside the database to store the video info.
#             Display this row in the teachers course list
#             """
#             sql_operation(table="course", mode="insert_draft",courseID=courseID, teacherID=userInfo.uid,videoPath=filePathToStore)
#             return redirect(url_for("teacherBP.createCourse", courseID=courseID))
#         else:
#             return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)
#     else:
#         return redirect(url_for("guestBP.login"))

@csrf.exempt
@teacherBP.route("/upload-video", methods=["GET", "POST"])
def videoUpload():
    if ("video_saving" not in session):
        courseID = generate_id()
        session["video_saving"] = [courseID, None] # Saving started; interruption = restart from scratch
    else:
        courseID = session["video_saving"][0]
        try:
            resp = request.json
            session["video_saving"] = [courseID, resp["hash"]]
        except Exception as e:
            # print(e)
            # write_log_entry(logMessage=f"Error in videoUpload: {e}", severity="WARNING")
            # return make_response("Unexpected error", 500)
            pass
        #TODO : Find a way to check if this was the file currently being saved or not

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    if (request.method == "POST"):
        file = request.files["videoUpload"]
        filename = courseID + Path(secure_filename(file.filename)).suffix # change filename to courseid.mp4
        totalChunks = int(request.form["dztotalchunkcount"])
        currentChunk = int(request.form['dzchunkindex'])
        if (filename == ""):
            flash("Please Upload a Video", "File Upload Error!")
            return redirect(url_for("teacherBP.videoUpload"))

        if (Path(filename).suffix not in current_app.config["ALLOWED_VIDEO_EXTENSIONS"]):
            flash("Unsupported format!", f"Please use only the following: \n{current_app.config['ALLOWED_VIDEO_EXTENSIONS']}")

        # folder creation
        current_app.config["COURSE_VIDEO_FOLDER"].joinpath(courseID).mkdir(parents=True, exist_ok=True)

        filePathToStore  = url_for("static", filename=f"course_videos/{courseID}/{filename}") # path for mp4 file stored in sql
        print("Total file size:", int(request.form["dztotalfilesize"]))
        absFilePath = current_app.config["COURSE_VIDEO_FOLDER"].joinpath(courseID, filename)

        try:
            with open(absFilePath, "ab") as videoData: # ab flag for opening a file for appending data in binary format
                videoData.seek(int(request.form["dzchunkbyteoffset"]))
                print("dzchunkbyteoffset:", int(request.form["dzchunkbyteoffset"]))
                videoData.write(file.stream.read())
        except (OSError):
            print("Could not write to file")
            return make_response("Error writing to file", 500)
        except:
            print("Unexpected error.")
            return make_response("Unexpected error", 500)

        if (currentChunk + 1 == totalChunks):
            # This was the last chunk, the file should be complete and the size we expect
            if (absFilePath.stat().st_size != int(request.form["dztotalfilesize"])):
                print(f"File {filename} was completed, but there is a size mismatch. Received {absFilePath.stat().st_size} but had expected {request.form['dztotalfilesize']}")
                # remove corrupted image
                absFilePath.unlink(missing_ok=True) # missing_ok argument is set to True as the file might not exist (>= Python 3.8)
                #pop to prevent further error
                session.pop("video_saving", None)
                return make_response("Uploaded image is corrupted! Please try again!", 500)
            else:
                print(f"File {filename} has been uploaded successfully")

                # COMPARISON OF HASH
                hashNum = session["video_saving"][1]
                if (hashNum):
                    with open(absFilePath, "rb") as f:
                        fileHash = hashlib.sha512(f.read()).hexdigest()

                    if (fileHash != hashNum):
                        print("File Hash is incorrect")
                        absFilePath.unlink(missing_ok=True)
                        session.pop("video_saving", None)
                        return make_response("Uploaded image is corrupted! Please try again!", 500)

                if (platform.system() != "Darwin"):
                    if (not convert_to_mpd(courseID, Path(filename).suffix)): # Error with conversion
                        flash("Invalid Video!", "File Upload Error!")
                        return redirect(url_for("teacherBP.videoUpload"))

                # constructing a file path to see if the user has already uploaded an image and if the file exists
                sql_operation(
                    table="course",
                    mode="insert_draft",
                    courseID=courseID,
                    teacherID=userInfo.uid,
                    videoPath=filePathToStore
                    # videoPath=Path(filePathToStore).with_suffix(".mpd")
                )
                session.pop("video_saving", None)
                return redirect(url_for("teacherBP.createCourse", courseID=courseID))
        else:
            return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)
    else:
        return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)

#TODO: Hash Video data, implement dropzone to encrpyt video data
@teacherBP.route("/create-course/<string:courseID>", methods=["GET","POST"])
def createCourse(courseID:str):
    if ("video_saving" in session):
        session.pop("video_saving", None)

    courseTuple = sql_operation(table="course", mode="get_draft_course_data", courseID=courseID)
    if (not courseTuple):
        flash("Course Already Created / Draft Does not exist!", "Course Creation error")
        return redirect(url_for("teacherBP.courseList"))
    videoFilePath = Path(current_app.config["COURSE_VIDEO_FOLDER"]).joinpath(courseID)
    videoFilename = courseID + Path(courseTuple[2]).suffix
    absFilePath = videoFilePath.joinpath(videoFilename)

    videoPath = url_for("static", filename=f"course_videos/{courseID}/{courseID}.mpd")

    if (not courseTuple):
        flash("No Course Found", "Course Not Found!")
        return redirect(url_for("teacherBP.draftCourseList"))

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    if (userInfo.role != "Teacher"):
        abort(500)

    courseForm = CreateCourse(request.form)
    if (request.method == "POST" and courseForm.validate()):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Please verify that you are not a bot!", "Danger")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=courseTuple[2])

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="create_course")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Please verify that you are not a bot!", "Danger")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=courseTuple[2])

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.75)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Please check the reCAPTCHA box and try again.", "Danger")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=courseTuple[2])

        courseTitle = courseForm.courseTitle.data
        courseDescription = courseForm.courseDescription.data
        courseTagInput = request.form.get("courseTag")
        coursePrice = float(courseForm.coursePrice.data)

        file = request.files.get("courseThumbnail")
        filename = secure_filename(file.filename)
        if (filename == "" or not accepted_file_extension(filename=filename, typeOfFile="image")):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=courseTuple[2])

        filePath = Path(generate_id(sixteenBytesTimes=2) + Path(filename).suffix)
        imageData = BytesIO(file.read())
        try:
            imageUrlToStore = compress_and_resize_image(
                imageData=imageData, imagePath=filePath, dimensions=(1920, 1080),
                folderPath=f"course-thumbnails"
            )
        except (InvalidProfilePictureError):
            flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=courseTuple[2])
        except (UploadFailedError):
            flash(Markup("Sorry, there was an error uploading your course thumbnail...<br>Please try again later!"), "Failed to Upload Course Thumbnail!")
            return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=courseTuple[2])

        videoPath = upload_file_from_path(
            bucketName=current_app.config["CONSTANTS"].COURSE_VIDEOS_BUCKET_NAME,
            localFilePath=absFilePath,
            uploadDestination=f"videos"
            # uploadDestination=f"videos/{videoFilename}" # folder created
        )
        # Delete video from storage (relying on mpd file)
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
        return redirect(url_for("userBP.userProfile"))
    else:
        return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseID, videoPath=videoPath)

""" End Of Course Creation """

""" Start Of Course Management """

"""
@teacherBP.route("/static/course_videos/<string:courseID>/<string:videoName>")
def rawVideo(courseID:str, videoName:str):
    if (sql_operation(table="course", mode="check_if_course_owned_by_teacher", teacherID=session["user"], courseID=courseID)):
        pass # allow access to the video for the teacher user if they own the course
    elif (sql_operation(table="course", mode="get_draft_course_data", courseID=courseID)):
        pass # allow access to the video if the teacher user is in the midst of creating the course
    else:
        abort(404)

    # TODO: Fix SQL query to get the video path (Index out of error)
    courseTuple = sql_operation(table="course", mode="get_draft_course_data", courseID=courseID)
    # Allow the teacher to see the video if the teacher is in the midst of creating the course
    if (courseTuple):
        filePathArr = courseTuple[2].rsplit("/", 2)[-2:]
        return send_from_directory(
            str(current_app.config["COURSE_VIDEO_FOLDER"].joinpath(filePathArr[0])),
            filePathArr[1],
            as_attachment=False,
            max_age=31536000
        )
    else:
        abort(404)

"""
@teacherBP.route("/delete-course", methods=["GET", "POST"])
def courseDelete():
    courseID = request.args.get("cid", default="test", type=str)
    sql_operation(table="course", mode="delete", courseID=courseID)
    print("Course Deleted")
    return redirect(url_for("teacherBP.courseList"))

@teacherBP.route("/delete-draft-course", methods=["GET", "POST"])
def draftCourseDelete():
    courseID = request.args.get("cid", default="test", type=str)
    courseFound = sql_operation(table="course", mode="get_draft_course_data", courseID=courseID)
    if (not courseFound):
        abort(404)

    shutil.rmtree(
        current_app.config["COURSE_VIDEO_FOLDER"].joinpath(secure_filename(courseID)),
        ignore_errors=False,
        onerror=lambda func, path, exc_info: write_log_entry(
            logMessage=f"Error deleting {courseID} folder at \"{path}\": {exc_info}", 
            severity="WARNING"
        )
    )
    sql_operation(table="course", mode="delete_from_draft", courseID=courseID)
    print("Draft Course Deleted")
    return redirect(url_for("teacherBP.draftCourseList"))

@teacherBP.route("/edit-course", methods=["GET", "POST"])
def courseUpdate():
    courseID = request.args.get("cid", default="test", type=str)
    courseFound = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courseFound):
        abort(404)

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    courseForm = CreateCourseEdit(request.form)
    updated = ""

    if (request.method == "POST"):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Please verify that you are not a bot!", "Danger")

    courseID = request.args.get("cid", default="test", type=str)
    courseFound = sql_operation(table="course", mode="get_course_data", courseID=courseID)
    if (not courseFound):
        abort(404)

    userInfo = get_image_path(session["user"], returnUserInfo=True)
    courseForm = CreateCourseEdit(request.form)
    updated = ""
    if (request.method == "POST"):
        recaptchaToken = request.form.get("g-recaptcha-response")
        if (recaptchaToken is None):
            flash("Please verify that you are not a bot!", "Danger")
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)

        try:
            recaptchaResponse = create_assessment(recaptchaToken=recaptchaToken, recaptchaAction="edit_course")
        except (InvalidRecaptchaTokenError, InvalidRecaptchaActionError):
            flash("Please verify that you are not a bot!", "Danger")
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)

        if (not score_within_acceptable_threshold(recaptchaResponse.risk_analysis.score, threshold=0.75)):
            # if the score is not within the acceptable threshold
            # then the user is likely a bot
            # hence, we will flash an error message
            flash("Please check the reCAPTCHA box and try again.", "Danger")
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)

        if (courseForm.courseTitle.data):
            if (courseForm.courseTitle.data != courseFound.courseName):
                sql_operation(table="course", mode="update_course_title", courseID=courseID, courseTitle=courseForm.courseTitle.data)
                stripe_product_update(courseID=courseID, courseName=courseForm.courseTitle.data)
                updated += "Course Title, "

        if (courseForm.courseDescription.data):
            if (courseForm.courseDescription.data != courseFound.courseDescription):
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
            updated += "Course Thumbnail, "

        if (len(updated) > 0):
            flash(f"Fields Updated : {updated}", "Successful Update")
        return redirect(url_for("teacherBP.courseList"))

    return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory, videoPath=courseFound.videoPath)

""" End Of Course Management """
