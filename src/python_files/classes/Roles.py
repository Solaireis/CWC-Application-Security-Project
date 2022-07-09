class RoleInfo:
    def __init__(self, tupleData:tuple=None):
        """
        Creates a review object in this format, 
        ('76456a9aa7104d7db2c89b24cab697c4', 'Test_Course_ID_1_v2', 2, 'This is a test review', datetime.datetime(2022, 6, 27, 21, 15, 1))

        Args:
        - user_id
        
        Note that all attributes are public.
        """
        self.role_id = tupleData[0]
        self.role_name= tupleData[1]
        self.guest_bp = tupleData[2]
        self.general_bp = tupleData[3]
        self.admin_bp = tupleData[4]
        self.logged_in_bp = tupleData[5]
        self.error_bp = tupleData[6]
        self.teacher_bp = tupleData[7]
        self.user_bp = tupleData[8]