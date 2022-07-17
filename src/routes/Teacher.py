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
from python_files.classes.Forms import *
from python_files.classes.MarkdownExtensions import AnchorTagPreExtension, AnchorTagPostExtension

# import python standard libraries
from pathlib import Path
from io import BytesIO

teacherBP = Blueprint("teacherBP", __name__, static_folder="static", template_folder="template")

@teacherBP.route("/course-video-list")
def courseList():
    if ("user" in session):
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
    else:
        return redirect(url_for("guestBP.login"))

@teacherBP.route("/draft-course-video-list")
def draftCourseList():
    if ("user" in session):
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
    
        return render_template("users/general/course_list.html", imageSrcPath=userInfo.profileImage, courseListLen=len(courseList), accType=userInfo.role, currentPage=page, maxPage=maxPage, courseList=courseList, isOwnself=True, paginationArr=paginationArr)
    else:
        return redirect(url_for("guestBP.login"))

""" Start Of Course Creation """

@teacherBP.route("/upload-video", methods=["GET", "POST"])
def videoUpload():
    if ("user" in session):
        courseID = generate_id()
        userInfo = get_image_path(session["user"], returnUserInfo=True)
        if (userInfo.role != "Teacher"):
            abort(404)

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

            #TODO : Finish Drafting
            """
            Create a row inside the database to store the video info.
            Display this row in the teachers course list 
            """
            # sql_operation(table="course", mode="insert",courseID=courseID, teacherID=userInfo.uid, courseName="UNSET", courseDescription="UNSET", courseImagePath="UNSET", courseCategory="UNSET", coursePrice=123, videoPath=filePathToStore)
            session["course-data"] = (courseID, filePathToStore)
            return redirect(url_for("teacherBP.createCourse"))
        else:
            return render_template("users/teacher/video_upload.html",imageSrcPath=userInfo.profileImage, accType=userInfo.role)
    else:
        return redirect(url_for("guestBP.login"))

#TODO: Hash Video data, implement dropzone to encrpyt video data
@teacherBP.route("/create-course", methods=["GET","POST"])
def createCourse():
    if ("user" in session):
        if ("course-data" in session):
            courseData = session["course-data"]
            userInfo = get_image_path(session["user"], returnUserInfo=True)
            if (userInfo.role != "Teacher"):
                abort(500)

            courseForm = CreateCourse(request.form)
            if (request.method == "POST"):
                courseTitle = courseForm.courseTitle.data
                courseDescription = courseForm.courseDescription.data
                courseTagInput = request.form.get("courseTag")
                coursePrice = float(courseForm.coursePrice.data)

                file = request.files.get("courseThumbnail")
                filename = secure_filename(file.filename)
                if (filename == "" or not accepted_file_extension(filename=filename, typeOfFile="image")):
                    flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
                    return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseData[0], videoPath=courseData[1])

                filePath = Path(generate_id(sixteenBytesTimes=2) + Path(filename).suffix)
                imageData = BytesIO(file.read())
                try:
                    imageUrlToStore = compress_and_resize_image(
                        imageData=imageData, imagePath=filePath, dimensions=(1920, 1080), 
                        folderPath=f"course-thumbnails"
                    )
                except (InvalidProfilePictureError):
                    flash("Please upload an image file of .png, .jpeg, .jpg ONLY.", "Failed to Upload Course Thumbnail!")
                    return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseData[0], videoPath=courseData[1])
                except (UploadFailedError):
                    flash(Markup("Sorry, there was an error uploading your course thumbnail...<br>Please try again later!"), "Failed to Upload Course Thumbnail!")
                    return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseData[0], videoPath=courseData[1])

                sql_operation(table="course", mode="insert",courseID=courseData[0], teacherID=userInfo.uid, courseName=courseTitle, courseDescription=courseDescription, courseImagePath=imageUrlToStore, courseCategory=courseTagInput, coursePrice=coursePrice, videoPath=courseData[1])
                stripe_product_create(courseID=courseData[0], courseName=courseTitle, courseDescription=courseDescription, coursePrice=coursePrice, courseImagePath=imageUrlToStore)


                session.pop("course-data")
                flash("Course Created", "Successful Course Created!")
                return redirect(url_for("userBP.userProfile"))
            else:
                return render_template("users/teacher/create_course.html", imageSrcPath=userInfo.profileImage, form=courseForm, accType=userInfo.role, courseID=courseData[0], videoPath=courseData[1])
        else:
            flash("No Video Uploaded", "File Upload Error!")
            return redirect(url_for("teacherBP.videoUpload"))
    else:
        return redirect(url_for("guestBP.login"))

""" End Of Course Creation """

""" Start Of Course Management """
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
    #TODO: Form is working, gonna make edits soon
    if ("user" in session):
        courseID = request.args.get("cid", default="test", type=str)
        courseFound = sql_operation(table="course", mode="get_course_data", courseID=courseID)
        if (not courseFound):
            abort(404)
        userInfo = get_image_path(session["user"], returnUserInfo=True) 
        courseForm = CreateCourseEdit(request.form)
        updated = ''
        if (request.method == "POST"):
            #TODO : Update profile picture, course tag
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
        else:
            
            return render_template("users/teacher/course_video_edit.html",form=courseForm, imageSrcPath=userInfo.profileImage, accType=userInfo.role, imagePath=courseFound.courseImagePath, courseName=courseFound.courseName, courseDescription=courseFound.courseDescription, coursePrice=courseFound.coursePrice, courseTag=courseFound.courseCategory)
    else:
        return redirect(url_for("guestBP.login"))

""" End Of Course Management """