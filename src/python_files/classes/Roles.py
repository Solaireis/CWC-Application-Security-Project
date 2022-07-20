class RoleInfo:
    def __init__(self, tupleData:tuple=None):
        """
        Creates a review object in this format, 
        ('76456a9aa7104d7db2c89b24cab697c4', 'Test_Course_ID_1_v2', 2, 'This is a test review', datetime.datetime(2022, 6, 27, 21, 15, 1))

        Args:
        - user_id
        
        Note that all attributes are public.
        """
        self.__role_id = tupleData[0]
        self.__role_name= tupleData[1]
        self.__guest_bp = tupleData[2]
        self.__general_bp = tupleData[3]
        self.__admin_bp = tupleData[4]
        self.__logged_in_bp = tupleData[5]
        self.__error_bp = tupleData[6]
        self.__teacher_bp = tupleData[7]
        self.__user_bp = tupleData[8]
        self.__super_admin_bp = tupleData[9]

    @property
    def role_id(self) -> str:
        return self.__role_id
    @property
    def role_name(self) -> str:
        return self.__role_name
    @property
    def guest_bp(self) -> int:
        return self.__guest_bp
    @property
    def general_bp(self) -> int:
        return self.__general_bp
    @property
    def admin_bp(self) -> int:
        return self.__admin_bp
    @property
    def logged_in_bp(self) -> int:
        return self.__logged_in_bp
    @property
    def error_bp(self) -> int:
        return self.__error_bp
    @property
    def teacher_bp(self) -> int:
        return self.__teacher_bp
    @property
    def user_bp(self) -> int:
        return self.__user_bp
    @property
    def super_admin_bp(self) -> int:
        return self.__super_admin_bp