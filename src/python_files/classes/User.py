# import python standard libraries
from datetime import datetime

class UserInfo:
    """
    This class is used to store the user info for code readability in jinja2 templates.

    tupleInfo Tuple format (13 elements):
    (
        row_num,
        u.id, r.role_name, u.username, 
        u.email, u.email_verified, u.password, 
        u.profile_image, u.date_joined, u.cart_courses, 
        u.purchased_courses, u.status, t.token AS has_two_fa
    )
    """
    def __init__(self, tupleData:tuple=None, userProfile:str=""):
        """
        Constructor for user object.

        Args:
        - tupleInfo (tuple): Tuple retrieved from the sql query using the stored procedure, "get_user_data".
            - Tuple format (13 elements): (\n
                    row_num, # IMPORTANT FOR THIS CLASS ELSE THE ORDER OF THE DATA WILL BE INCORRECT\n
                    u.id, r.role_name, u.username,\n
                    u.email, u.email_verified, u.password,\n
                    u.profile_image, u.date_joined, u.cart_courses,\n
                    u.purchased_courses, u.status, t.token AS has_two_fa
                )
        - userProfile (str): The dicebear url or the path to the user's profile picture
        """
        self.__uid = tupleData[1]
        self.__role = tupleData[2]
        self.__username = tupleData[3]
        self.__email = tupleData[4]
        self.__emailVerified = tupleData[5]
        self.__googleOAuth = True if (tupleData[6] is None) else False
        self.__profileImage = userProfile # Note: Use get_dicebear_image() on the username if the profile image is None
        self.__dateJoined = tupleData[8]
        self.__cartCourses = tupleData[9]
        self.__purchasedCourses = tupleData[10]
        self.__status = tupleData[11]
        self.__hasTwoFA = True if (tupleData[12] is not None) else False

    @property
    def uid(self) -> str:
        return self.__uid
    @property
    def role(self) -> str:
        return self.__role
    @property
    def username(self) -> str:
        return self.__username
    @property
    def email(self) -> str:
        return self.__email
    @property
    def emailVerified(self) -> bool:
        return self.__emailVerified
    @property
    def googleOAuth(self) -> bool:
        return self.__googleOAuth
    @property
    def profileImage(self) -> str:
        return self.__profileImage
    @property
    def dateJoined(self) -> datetime:
        return self.__dateJoined
    @property
    def cartCourses(self) -> str:
        return self.__cartCourses
    @property
    def purchasedCourses(self) -> str:
        return self.__purchasedCourses
    @property
    def status(self) -> str:
        return self.__status
    @property
    def hasTwoFA(self) -> bool:
        return self.__hasTwoFA

    def __repr__(self) -> str:
        return f"\nUID: {self.uid} " + \
               f"| Role: {self.role} " + \
               f"| Username: {self.username} " + \
               f"| Email: {self.email} " + \
               f"| Email Verified: {self.emailVerified} " + \
               f"| Enabled 2FA: {self.hasTwoFA} " + \
               f"| Google OAuth: {self.googleOAuth} " + \
               f"| Profile Image: {self.profileImage} " + \
               f"| Date Joined: {self.dateJoined} " + \
               f"| Cart Courses: {self.cartCourses} " + \
               f"| Purchased Courses: {self.purchasedCourses} " + \
               f"| Status: {self.status}"