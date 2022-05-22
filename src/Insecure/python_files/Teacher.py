from .Common import Common

# Created by Jason and edited by Wei Ren

class Teacher(Common):
    def __init__(self, user_id, username, email, password):
        super().__init__(user_id, username, email, password, "Teacher", "Good")
        self.__earnings = 0
        self.__accumulated_earnings = 0
        self.__paypalID = "" # PayPal Account ID
        self.__bio = ""
        # Added by Wei Ren for courses
        self.__coursesTeaching = [] # Course IDs here
        # Added by Wei Ren for Cashout
        self.__cashoutPreference = "Email" # Uses normal email
        self.__phoneVerification = "Not Verified"
        self.__cashoutPhone = None

    """Done by Jason"""
    
    def set_earnings(self, earnings):
        self.__earnings = float(earnings)
    def get_earnings(self):
        return self.__earnings

    def set_bio(self, bio):
        self.__bio = bio
    def get_bio(self):
        return self.__bio

    def set_accumulated_earnings(self, earnings):
        self.__accumulated_earnings = float(earnings)
    def get_accumulated_earnings(self):
        return self.__accumulated_earnings

    """End of Done by Jason"""

    """Done by Wei Ren"""

    def get_coursesTeaching(self):
        return self.__coursesTeaching
    def set_courseTeaching(self, courseID):
        self.__coursesTeaching.append(courseID)
    def remove_courseTeaching(self, courseID):
        self.__coursesTeaching.remove(courseID)

    def set_paypalID(self, paypalID):
        self.__paypalID = paypalID
    def get_paypalID(self):
        return self.__paypalID

    def get_cashoutPhone(self):
        return self.__cashoutPhone
    def set_cashoutPhone(self,cashoutPhone):
        self.__cashoutPhone = cashoutPhone

    def get_cashoutPreference(self):
        return self.__cashoutPreference
    def set_cashoutPreference(self, cashoutPreference):
        self.__cashoutPreference = cashoutPreference

    def get_phoneVerification(self):
        return self.__phoneVerification
    def set_phoneVerification(self,phoneVerification):
        self.__phoneVerifircation = phoneVerification

    """"End of Done by Wei Ren"""
