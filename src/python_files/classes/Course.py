# import python standard libraries
from datetime import datetime

# import local python libraries
from .Constants import CONSTANTS

def get_readable_category(courseCategory:str="") -> str:
    """
    Get the readable category name from the course category.

    E.g. "Programming" -> "Development - Programming"

    Args:
    - courseCategory (str): The course category ID.
        - e.g. "Programming", "Test_Prep", etc.

    Returns:
    - str: The readable category name or "Unknown Category" if the category is not found.
    """
    return CONSTANTS.CATEGORY_TABLE.get(courseCategory, "Unknown Category")

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
    def __init__(self, 
        tupleInfo:tuple="",
        profilePic:str="", 
        truncateData:bool=False, 
        draftStatus:bool=False,
        getReadableCategory=False
    ):
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
        - draftStatus (bool): True if the course is a draft, False if it is not
        - getReadableCategory (bool): True if the course category should be converted to a readable category, False if not
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
            self.__courseCategory = tupleInfo[8] if (not getReadableCategory) \
                                                 else get_readable_category(tupleInfo[8])
            self.__dateCreated = tupleInfo[9]
            self.__averageRating = int(tupleInfo[10]) if (tupleInfo[10] is not None) else 0
            self.__videoPath = tupleInfo[11]
            self.__status = tupleInfo[-1]

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
    @property
    def status(self) -> str:
        return self.__status

    def __repr__(self) -> str:
        """Returns a string representation of the course info object."""
        return f"\n[Course Info: {self.courseName} | " + \
               f"By: {self.teacherUsername} | " + \
               f"Price: ${self.coursePrice} | " + \
               f"Category: {self.courseCategory} | " + \
               f"Date Created: {self.dateCreated} | " + \
               f"Average Rating: {self.averageRating} | "