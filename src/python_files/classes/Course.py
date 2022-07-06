# import python standard libraries
import warnings

class Course:
    def __init__(self, tupleInfo:tuple, truncateData:bool=False) -> None:
        """
        WARNING:
        - THIS COURSE OBJECT IS DEPRECATED!
        - Please use the CourseInfo object instead!

        Creates a course object in this format, 
        [(("Daniel", "daniel_profile_image"), (course_id, teacher_name, course_name,...))]

        Basically a tuple of a tuple of the teacher's username and profile pic and 
        a tuple of the course info tuple.

        Note that all attributes are public.
        """
        warnings.warn("Course object is now deprecated! Please use CourseInfo object instead!", DeprecationWarning)
        self.teacher_name = tupleInfo[0][0]
        self.teacher_profile_image = tupleInfo[0][1][0]
        self.dicebear_profile_image = tupleInfo[0][1][1]
        self.course_id = tupleInfo[1][0]
        self.teacher_id = tupleInfo[1][1]
        self.course_name = tupleInfo[1][2]
        self.course_description = tupleInfo[1][3]
        if (truncateData):
            # Limit to 300 characters
            self.course_description = self.course_description[:300].strip() + "..."
        self.course_image_path = tupleInfo[1][4]
        self.course_price = f"${round(float(tupleInfo[1][5]), 2):.2f}"
        self.course_category = tupleInfo[1][6]
        self.course_date_created = tupleInfo[1][7]

        # total ratings score / num of ratings
        self.rating_count = tupleInfo[1][9]
        self.total_rating_score = tupleInfo[1][8]
        if (self.rating_count == 0):
            self.average_rating = 0
        else:
            self.average_rating = int(round(self.total_rating_score / self.rating_count, 0)) 

    def __repr__(self) -> str:
        return f"\n[Course: {self.course_name} | " + f"By: {self.teacher_name} | " + f"Price: ${self.course_price} | " + f"Category: {self.course_category} | " + f"Date Created: {self.course_date_created} | " + f"Rating: {self.average_rating} ]\n"

class CourseInfo:
    """
    This class is used to store the course info for code readability in jinja2 templates.

    tupleInfo Tuple format (12 elements):
    (
        c.course_id, c.teacher_id, u.username, u.profile_pic,
        c.course_name, c.course_description, c.course_image_path, c.course_price, 
        c.course_category, c.date_created, c.course_total_rating, c.course_rating_count
    )
    """
    def __init__(self, tupleInfo:tuple="", profilePic:str="", truncateData:bool=False):
        """
        Constructor for course info object.
    
        Args:
        - tupleInfo (tuple): Tuple retrieved from the sql query
            - Tuple format (12 elements): (
                    c.course_id, c.teacher_id, u.username, u.profile_pic
                    c.course_name, c.course_description, c.course_image_path, c.course_price, 
                    c.course_category, c.date_created, c.course_total_rating, c.course_rating_count
                )
        - profilePic (str): The dicebear url or the path to the teacher's profile picture
        - truncateData (bool): Truncate the course description to 300 characters
        """
        self.teacherID = tupleInfo[1]
        self.teacherUsername = tupleInfo[2]
        self.teacherProfile = profilePic # Note: tupleInfo[3] is the profile pic but will not be used!
        self.courseName = tupleInfo[4]
        self.courseDescription = tupleInfo[5] if (not truncateData) \
                                              else tupleInfo[5][:300].strip() + "..."
        self.courseImagePath = tupleInfo[6]
        self.coursePrice = tupleInfo[7]
        self.courseCategory = tupleInfo[8]
        self.dateCreated = tupleInfo[9]
        self.averageRating = int(round(tupleInfo[10] / tupleInfo[11], 0)) \
                             if (tupleInfo[10] > 0) else 0

    def __repr__(self) -> str:
        """Returns a string representation of the course info object."""
        return f"\n[Course Info: {self.courseName} | " + \
               f"By: {self.teacherUsername} | " + \
               f"Price: ${self.coursePrice} | " + \
               f"Category: {self.courseCategory} | " + \
               f"Date Created: {self.dateCreated} | " + \
               f"Rating: {self.averageRating} ]\n"