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
                flash("Course Created", "Successful Course Created!")
                return redirect(url_for("userBP.userProfile"))
            else:
                return render_template("users/teacher/create_course.html", imageSrcPath=imageSrcPath, form=courseForm, accType=userInfo[1], courseID=courseData[0], videoPath=courseData[1])
        else:
            flash("No Video Uploaded", "File Upload Error!")
            return redirect(url_for("userBP.videoUpload"))
    else:
        return redirect(url_for("guestBP.login"))

@teacherBP.route("/course-video-list")
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

@teacherBP.route("/delete-course", methods=["GET", "POST"])
def courseDelete():
    if ("user" in session):
        courseID = request.args.get("cid", default="test", type=str)
        sql_operation(table="course", mode="delete", courseID=courseID)
        print("Course Deleted")
        return redirect(url_for("userBP.courseList"))
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