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