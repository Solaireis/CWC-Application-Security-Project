from datetime import datetime

class Reviews:
    def __init__(self, tupleData:tuple=None, courseID:str=None, profileImage:str=None):
        """
        Creates a review object in this format, 
        ('76456a9aa7104d7db2c89b24cab697c4', 'Test_Course_ID_1_v2', 2, 'This is a test review', datetime.datetime(2022, 6, 27, 21, 15, 1))

        Args:
        - tupleData (tuple): Tuple retrieved from the sql query
        - courseID (str): The course ID of the course the review is for
        - profileImage (str): The dicebear url or the path to the user's profile picture
        """
        self.__user_id = tupleData[0]
        self.__course_id = courseID
        self.__rating = tupleData[2]
        self.__review = tupleData[3]
        self.__date_created = tupleData[4]
        self.__username = tupleData[5]
        self.__profile_image = profileImage

    @property
    def user_id(self) -> str:
        return self.__user_id
    @property
    def course_id(self) -> str:
        return self.__course_id
    @property
    def rating(self) -> int:
        return self.__rating
    @property
    def review(self) -> str:
        return self.__review
    @property
    def date_created(self) -> datetime:
        return self.__date_created
    @property
    def username(self) -> str:
        return self.__username
    @property
    def profile_image(self) -> str:
        return self.__profile_image