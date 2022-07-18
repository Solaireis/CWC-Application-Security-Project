# import python standard libraries
from datetime import datetime
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

    tupleInfo Tuple format (13 elements):
    (
        c.course_id, c.teacher_id, 
        u.username, u.profile_image, c.course_name, c.course_description,
        c.course_image_path, c.course_price, c.course_category, c.date_created, 
        c.avg_rating, number_of_results
    )
    """
    def __init__(self, tupleInfo:tuple="", profilePic:str="", truncateData:bool=False, draftStatus:bool=False):
        """
        Constructor for course info object.
    
        Args:
        - tupleInfo (tuple): Tuple retrieved from the sql query using the stored procedure, "get_course_data".
            - Tuple format (13 elements): (
                    c.course_id, c.teacher_id, 
                    u.username, u.profile_image, c.course_name, c.course_description,
                    c.course_image_path, c.course_price, c.course_category, c.date_created, 
                    c.avg_rating, number_of_results
                )
        - profilePic (str): The dicebear url or the path to the teacher's profile picture
        - truncateData (bool): Truncate the course description to 300 characters
        """
        self.__courseID = tupleInfo[0]
        self.__teacherID = tupleInfo[1]
        self.__teacherUsername = tupleInfo[2]
        self.__teacherProfile = profilePic # Note: Use get_dicebear_image(res[2]) if (res[3] is None) else res[3]
        if (not draftStatus):
            self.__courseName = tupleInfo[4]
            self.__courseDescription = tupleInfo[5] if (not truncateData) \
                                                else tupleInfo[5][:300].strip() + "..."
            self.__courseImagePath = tupleInfo[6]
            self.__coursePrice = tupleInfo[7]
            self.__courseCategory = tupleInfo[8]
            self.__dateCreated = tupleInfo[9]
            self.__averageRating = int(tupleInfo[10]) if (tupleInfo[10] is not None) else 0
            self.__videoPath = tupleInfo[11]

    @property
    def courseID(self) -> str:
        return self.__courseID
    @property
    def teacherID(self) -> str:
        return self.__teacherID
    @property
    def teacherUsername(self) -> str:
        return self.__teacherUsername
    @property
    def teacherProfile(self) -> str:
        return self.__teacherProfile
    @property
    def courseName(self) -> str:
        return self.__courseName
    @property
    def courseDescription(self) -> str:
        return self.__courseDescription
    @property
    def courseImagePath(self) -> str:
        return self.__courseImagePath
    @property
    def coursePrice(self) -> float:
        return self.__coursePrice
    @property
    def courseCategory(self) -> str:
        return self.__courseCategory
    @property
    def dateCreated(self) -> datetime:
        return self.__dateCreated
    @property
    def averageRating(self) -> int:
        return self.__averageRating
    @property
    def videoPath(self) -> str:
        return self.__videoPath


    def __repr__(self) -> str:
        """Returns a string representation of the course info object."""
        return f"\n[Course Info: {self.courseName} | " + \
               f"By: {self.teacherUsername} | " + \
               f"Price: ${self.coursePrice} | " + \
               f"Category: {self.courseCategory} | " + \
               f"Date Created: {self.dateCreated} | " + \
               f"Average Rating: {self.averageRating} | "