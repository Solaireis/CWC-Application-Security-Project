"""
Routes for logged in Teachers
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
from pathlib import Path
from io import BytesIO

teacherBP = Blueprint("teacherBP", __name__, static_folder="static", template_folder="template")

#TODO: Hash Video data, implement dropzone to encrpyt video data
@teacherBP.route("/create-course", methods=["GET","POST"])
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
                filename = secure_filename(file.filename)
                if (filename == "" or not accepted_image_extension(filename)):
                    flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
                    return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1], courseID=courseData[0], videoPath=courseData[1])

                filePath = Path(generate_id(sixteenBytesTimes=2) + Path(filename).suffix)
                imageData = BytesIO(file.read())
                try:
                    imageUrlToStore = compress_and_resize_image(
                        imageData=imageData, imagePath=filePath, dimensions=(1920, 1080), 
                        folderPath=f"course-thumbnails"
                    )
                except (InvalidProfilePictureError):
                    flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
                    return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1], courseID=courseData[0], videoPath=courseData[1])
                except (UploadFailedError):
                    flash(Markup("Sorry, there was an error uploading your profile picture...<br>Please try again later!"), "Failed to Upload Course Thumbnail!")
                    return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1], courseID=courseData[0], videoPath=courseData[1])

                sql_operation(table="course", mode="insert",courseID=courseData[0], teacherID=userInfo[0], courseName=courseTitle, courseDescription=courseDescription, courseImagePath=imageUrlToStore, courseCategory=courseTagInput, coursePrice=coursePrice, videoPath=courseData[1])
                stripe_product_create(courseID=courseData[0], courseName=courseTitle, courseDescription=courseDescription, coursePrice=coursePrice, courseImagePath=imageUrlToStore)


                session.pop("course-data")
                flash("Course Created", "Successful Course Created!")
                return redirect(url_for("userBP.userProfile"))
            else:
                return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1], courseID=courseData[0], videoPath=courseData[1])
        else:
            flash("No Video Uploaded", "File Upload Error!")
            return redirect(url_for("teacherBP.videoUpload"))
    else:
        return redirect(url_for("guestBP.login"))

@teacherBP.route("/course-video-list")
def courseList():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        page = request.args.get("p", default=1, type=int)
        courseList = sql_operation(table="course", mode="get_all_courses_by_teacher", teacherID=userInfo[0], pageNum=page)
        maxPage = 0
        if len(courseList)!= 0:
            courseList, maxPage = courseList[0], courseList[1]         
            if (page > maxPage):
                abort(404)
        
        return render_template("users/teacher/course_list.html", imageSrcPath=imageSrcPath, courseListLen=len(courseList), accType=userInfo[1], pageNum=page, maxPage=maxPage, courseList=courseList)

    else:
        return redirect(url_for("guestBP.login"))

@teacherBP.route("/delete-course", methods=["GET", "POST"])
def courseDelete():
    if ("user" in session):
        courseID = request.args.get("cid", default="test", type=str)
        sql_operation(table="course", mode="delete", courseID=courseID)
        print("Course Deleted")
        return redirect(url_for("teacherBP.courseList"))
    else:
        return redirect(url_for("guestBP.login"))

@teacherBP.route("/edit-course", methods=["GET", "POST"])
def courseUpdate():
    if ("user" in session):
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        #TODO: Make the update video details form
    else:
        return redirect(url_for("guestBP.login"))

@teacherBP.route("/upload-video", methods=["GET", "POST"])
def videoUpload():
    if ("user" in session):
        courseID = generate_id()
        imageSrcPath, userInfo = get_image_path(session["user"], returnUserInfo=True)
        if (userInfo[1] != "Teacher"):
            abort(500)

        if (request.method == "POST"):
            if (request.files["courseVideo"].filename == ""):
                flash("Please Upload a Video", "File Upload Error!")
                return redirect(url_for("teacherBP.videoUpload"))

            file = request.files.get("courseVideo")
            filename = secure_filename(file.filename)

            print(f"This is the filename for the inputted file : {filename}")

            filePath = Path(current_app.config["COURSE_VIDEO_FOLDER"]).joinpath(courseID)
            print(f"This is the folder for the inputted file: {filePath}")
            filePath.mkdir(parents=True, exist_ok=True)

            filePathToStore  = url_for("static", filename=f"course_videos/{courseID}/{filename}")
            file.save(Path(filePath).joinpath(filename))

            session["course-data"] = (courseID, filePathToStore)
            return redirect(url_for("teacherBP.createCourse"))
        else:
            return render_template("users/teacher/video_upload.html",imageSrcPath=imageSrcPath, accType=userInfo[1])
    else:
        return redirect(url_for("guestBP.login"))