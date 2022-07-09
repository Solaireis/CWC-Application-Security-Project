# import python standard libraries
from datetime import datetime
import json

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
    def __init__(self, tupleData:tuple=None, userProfile:str="", offset:int=0):
        """
        Constructor for user object.

        Args:
        - tupleInfo (tuple): Tuple retrieved from the sql query using the stored procedure, "get_user_data".
            - Tuple format (12 elements): (\n
                    u.id, r.role_name, u.username,\n
                    u.email, u.email_verified, u.password,\n
                    u.profile_image, u.date_joined, u.cart_courses,\n
                    u.purchased_courses, u.status, t.token AS has_two_fa
                )
        - userProfile (str): The dicebear url or the path to the user's profile picture
        - offset (int): The offset for indexing to get the correct user's data for each attribute.
            - Default: 0
            - E.g. offset=1 to account for the row number at the start of the tuple.
                - Tuple format (13 elements): (\n
                    row_num, # IMPORTANT THAT THIS EXTRA ATTRIBUTE MUST BE AT THE START\n
                    u.id, r.role_name, u.username,\n
                    u.email, u.email_verified, u.password,\n
                    u.profile_image, u.date_joined, u.cart_courses,\n
                    u.purchased_courses, u.status, t.token AS has_two_fa
                )
        """
        self.__uid = tupleData[0 + offset]
        self.__role = tupleData[1 + offset]
        self.__username = tupleData[2 + offset]
        self.__email = tupleData[3 + offset]
        self.__emailVerified = tupleData[4 + offset]
        self.__googleOAuth = True if (tupleData[5 + offset] is None) else False
        self.__profileImage = userProfile # Note: Use get_dicebear_image() on the username if the profile image is Nonew
        self.__hasProfilePic = False if (tupleData[6 + offset] is None) else True
        self.__dateJoined = tupleData[7 + offset]
        self.__cartCourses = json.loads(tupleData[8 + offset]) if (tupleData[8 + offset] is not None) else []
        self.__purchasedCourses = json.loads(tupleData[9 + offset]) if (tupleData[9 + offset] is not None) else []
        self.__status = tupleData[10 + offset]
        self.__hasTwoFA = True if (tupleData[11 + offset] is not None) else False

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
    @profileImage.setter
    def profileImage(self, profileImage:str):
        self.__profileImage = profileImage
    @property
    def hasProfilePic(self) -> bool:
        return self.__hasProfilePic
    @property
    def dateJoined(self) -> datetime:
        return self.__dateJoined
    @property
    def cartCourses(self) -> dict:
        return self.__cartCourses
    @property
    def purchasedCourses(self) -> dict:
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