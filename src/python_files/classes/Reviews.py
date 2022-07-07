from datetime import datetime

class Reviews:
    def __init__(self, tupleData:tuple=None, courseID:str=None, profileImage:str=None):
        """
        Creates a review object in this format, 
        ('76456a9aa7104d7db2c89b24cab697c4', 'Test_Course_ID_1_v2', 2, 'This is a test review', datetime.datetime(2022, 6, 27, 21, 15, 1))

        Args:
        - user_id
        
        Note that all attributes are public.
        """

        self.user_id = tupleData[0]
        self.course_id = courseID
        self.rating = tupleData[2]
        self.review = tupleData[3]
        self.date_created = tupleData[4]
        self.username = tupleData[5]
        self.profile_image = profileImage

