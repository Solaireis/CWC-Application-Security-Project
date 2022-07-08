class UserInfo:
    """
    This class is used to store the user info for code readability in jinja2 templates.

    tupleInfo Tuple format (12 elements):
    (
        u.id, r.role_name, u.username, 
        u.email, u.email_verified, u.password, 
        u.profile_image, u.date_joined, u.cart_courses, 
        u.purchased_courses, u.status, total_users
    )
    """
    def __init__(self, tupleData:tuple=None, userProfile:str=""):
        """
        Constructor for user object.

        Args:
        - tupleInfo (tuple): Tuple retrieved from the sql query using the stored procedure, "get_user_data".
            - Tuple format (12 elements): (
                    u.id, r.role_name, u.username, 
                    u.email, u.email_verified, u.password, 
                    u.profile_image, u.date_joined, u.cart_courses, 
                    u.purchased_courses, u.status, total_users
                )
        - userProfile (str): The dicebear url or the path to the user's profile picture
        """
        self.uid = tupleData[0]
        self.role = tupleData[1]
        self.username = tupleData[2]
        self.email = tupleData[3]
        self.emailVerified = tupleData[4]
        self.password = tupleData[5]
        self.googleOAuth = True if (tupleData[5] is None) else False
        self.profileImage = userProfile # Note: Use get_dicebear_image() on the username if the profile image is None
        self.dateJoined = tupleData[7]
        self.cartCourses = tupleData[8]
        self.purchasedCourses = tupleData[9]
        self.status = tupleData[10]

    def __repr__(self) -> str:
        return f"\nUID: {self.id} " + \
               f"| Role: {self.role} " + \
               f"| Username: {self.username} " + \
               f"| Email: {self.email} " + \
               f"| Email Verified: {self.emailVerified} " + \
               f"| Google OAuth: {self.googleOAuth} " + \
               f"| Profile Image: {self.profileImage} " + \
               f"| Date Joined: {self.dateJoined} " + \
               f"| Cart Courses: {self.cartCourses} " + \
               f"| Purchased Courses: {self.purchasedCourses} " + \
               f"| Status: {self.status}"