# import python standard libraries
from datetime import datetime
import json

class UserInfo:
    """This class is used to store the user info for code readability in jinja2 templates."""
    def __init__(self, tupleData:tuple=None, userProfile:str=""):
        """
        Constructor for user object.

        Args:
        - tupleInfo (tuple): Tuple retrieved from the sql query using the stored procedure, "get_user_data".
        - userProfile (str): The dicebear url or the path to the user's profile picture
        """
        self.__uid = tupleData[0]
        self.__role = tupleData[1]
        self.__username = tupleData[2]
        self.__email = tupleData[3]
        self.__emailVerified = tupleData[4]
        self.__googleOAuth = True if (tupleData[5] is None) else False
        self.__profileImage = userProfile # Note: Use get_dicebear_image() on the username if the profile image is None
        self.__hasProfilePic = False if (tupleData[6] is None) else True
        self.__dateJoined = tupleData[7]
        self.__cartCourses = json.loads(tupleData[8]) \
                                        if (tupleData[8] is not None) else []
        self.__status = tupleData[9]
        self.__hasTwoFA = True if (tupleData[10] is not None) else False

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
    def cartCourses(self) -> list:
        return self.__cartCourses
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
               f"| Status: {self.status}"