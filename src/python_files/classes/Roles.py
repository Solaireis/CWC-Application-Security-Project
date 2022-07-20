class RoleInfo:
    def __init__(self, tupleData:tuple=None):
        """
        Creates a review object in this format, 
        ('76456a9aa7104d7db2c89b24cab697c4', 'Test_Course_ID_1_v2', 2, 'This is a test review', datetime.datetime(2022, 6, 27, 21, 15, 1))

        Args:
        - user_id
        
        Note that all attributes are public.
        """
        self.__roleID = tupleData[0]
        self.__roleName= tupleData[1]
        self.__guestBP = bool(tupleData[2])
        self.__generalBP = bool(tupleData[3])
        self.__adminBP = bool(tupleData[4])
        self.__loggedInBP = bool(tupleData[5])
        self.__errorBP = bool(tupleData[6])
        self.__teacherBP = bool(tupleData[7])
        self.__userBP = bool(tupleData[8])
        self.__superAdminBP = bool(tupleData[9])

    @property
    def roleID(self) -> str:
        return self.__roleID
    @property
    def roleName(self) -> str:
        return self.__roleName
    @property
    def guestBP(self) -> bool:
        return self.__guestBP
    @property
    def generalBP(self) -> bool:
        return self.__generalBP
    @property
    def adminBP(self) -> bool:
        return self.__adminBP
    @property
    def loggedInBP(self) -> bool:
        return self.__loggedInBP
    @property
    def errorBP(self) -> bool:
        return self.__errorBP
    @property
    def teacherBP(self) -> bool:
        return self.__teacherBP
    @property
    def userBP(self) -> bool:
        return self.__userBP
    @property
    def superAdminBP(self) -> bool:
        return self.__superAdminBP