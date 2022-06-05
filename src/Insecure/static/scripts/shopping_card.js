function removeCourse(courseID) {
    document.getElementById("course-delete-field").value = courseID;
    document.getElementById("course-delete-form").submit()
}