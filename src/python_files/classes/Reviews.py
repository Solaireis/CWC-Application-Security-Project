class Reviews:
    def __init__(self, user_id,course_id,rating,review,date_created,username,profile_image):
        """
        Creates a review object in this format, 
        ('76456a9aa7104d7db2c89b24cab697c4', 'Test_Course_ID_1_v2', 2, 'This is a test review', datetime.datetime(2022, 6, 27, 21, 15, 1))

        
        Note that all attributes are public.
        """
        self.user_id = user_id
        self.course_id = course_id
        self.rating = rating
        self.review = review
        self.date_created = date_created
        self.username = username
        self.profile_image = profile_image

class ReviewList:
    def __init__(self, tupleInfo:tuple, truncateData:bool=False) -> None:
        """
        Creates a review object in this format, 
        [(("Daniel", "daniel_profile_image"), (course_id, teacher_name, course_name,...))]
        """
        self.user_id = tupleInfo[0][0]
        self.course_id = tupleInfo[0][1]
        self.rating = tupleInfo[0][2]
        self.review = tupleInfo[0][3]
        self.date_created = tupleInfo[0][4]
        self.username = tupleInfo[0][5]
        self.profile_image = tupleInfo[0][6]
        if (truncateData):
            # Limit to 300 characters
            self.review = self.review[:300].strip() + "..."
        self.rating_count = tupleInfo[0][7]
        self.total_rating_score = tupleInfo[0][8]
        if (self.rating_count == 0):
            self.average_rating = 0
        else:
            self.average_rating = int(round(self.total_rating_score / self.rating_count, 0))