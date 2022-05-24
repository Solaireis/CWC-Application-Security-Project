class Course:
    def __init__(self, tupleInfo):
        """
        Creates a course object in this format, 
        [(("Daniel", "daniel_profile_image"), (course_id, teacher_name, course_name,...))]
        
        Basically a tuple of a tuple of the teacher's username and profile pic and 
        a tuple of the course info tuple.
        
        Note that all attributes are public.
        """
        self.teacher_name = tupleInfo[0][0]
        self.teacher_profile_image = tupleInfo[0][1]
        self.course_id = tupleInfo[1][0]
        self.teacher_id = tupleInfo[1][1]
        self.course_name = tupleInfo[1][2]
        self.course_description = tupleInfo[1][3]
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

    def __repr__(self):
        return f"\n[Course: {self.course_name} | " + f"By: {self.teacher_name} | " + f"Price: ${self.course_price} | " + f"Category: {self.course_category} | " + f"Date Created: {self.course_date_created} | " + f"Rating: {self.average_rating} ]\n"