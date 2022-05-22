from .User import User
from datetime import date

# to check for unique values in a list or dictionary
# Done by Jason
def checkUniqueElements(inputToCheck):
    listOf = []
    if isinstance(inputToCheck, dict):
        for values in inputToCheck.values():
            listOf.append(values)
        uniqueNumbersOfViews = len(set(listOf)) # get numbers of unique values in dictionary
    elif isinstance(inputToCheck, list):
        for value in inputToCheck:
            listOf.append(value)
        uniqueNumbersOfViews = len(set(listOf)) # get numbers of unique values in the list
    else:
        raise Exception("Function checkUniqueElements can only accept dictionary or lists!")
    return uniqueNumbersOfViews

# Created by Jason and edited by Wei Ren and Royston

class Common(User):
    def __init__(self, user_id, username, email, password, acc_type, status):
        super().__init__(user_id, username, email, password, acc_type, status)
        self.__email_verification = "Not Verified"
        self.__teacher_joined_date = ""
        # Added by Wei Ren for Courses
        self.__shoppingCart = [] # Course IDs here
        self.__purchasedCourses = {} # Course IDs, Timing, Cost here
                                     # E.g. {courseID: {type: "Video", purchasedDate: "2020-01-01", cost: "100"}}
        self.__tags_viewed = {"Programming": 0,
                              "Web_Development": 0,
                              "Game_Development": 0,
                              "Mobile_App_Development": 0,
                              "Software_Development": 0,
                              "Other_Development": 0,
                              "Entrepreneurship": 0,
                              "Project_Management": 0,
                              "BI_Analytics": 0,
                              "Business_Strategy": 0,
                              "Other_Business": 0,
                              "3D_Modelling": 0,
                              "Animation": 0,
                              "UX_Design": 0,
                              "Design_Tools": 0,
                              "Other_Design": 0,
                              "Digital_Photography": 0,
                              "Photography_Tools": 0,
                              "Video_Production": 0,
                              "Video_Design_Tools": 0,
                              "Other_Photography_Videography": 0,
                              "Science": 0,
                              "Math": 0,
                              "Language": 0,
                              "Test_Prep": 0,
                              "Other_Academics": 0}

    """Done by Royston"""

    def add_purchase(self, courseID, value):
        self.__purchasedCourses[courseID] = value # courseID will be the key and the value will be a dictionary
    def set_purchases(self, purchasesDict): # if there's a need to replace a user's purchase dictionary
        self.__purchasedCourses = purchasesDict
    def get_purchases(self): # Get a dictionary of the user's purchased courses
        return self.__purchasedCourses
    
    """End of Done by Royston"""

    # Done by Wei Ren for scalability
    def remove_purchased_course(self, courseID): 
        if courseID in self.__purchasedCourses:
            self.__purchasedCourses.pop(courseID)
        else:
            return False

    """Done by Jason"""

    def set_tags_viewed(self, tagsDict):
        self.__tags_viewed = tagsDict
    def get_tags_viewed(self):
        return self.__tags_viewed
    def change_no_of_view(self, seenTag):
        userTagDict = self.__tags_viewed
        if seenTag in userTagDict:
            userTagDict[seenTag] += 1
        else:
            print("No such tag found.")
    def get_highest_tag(self):
        tagDict = self.__tags_viewed
        uniqueNumbersOfViews = checkUniqueElements(tagDict)
        if uniqueNumbersOfViews > 1:
            return max(tagDict, key=tagDict.get)
        else:
            return "No highly watched tag"
    # for scalability reasons but would not be used in this project
    def add_tag(self, newTag):
        self.__tags_viewed[newTag] = 0
    def remove_tag(self, tagToBeRemoved):
        self.__tags_viewed.pop(tagToBeRemoved)

    def set_email_verification(self, verify_email):
        self.__email_verification = verify_email
    def get_email_verification(self):
        return self.__email_verification

    def update_teacher_join_date_to_today(self):
        self.__teacher_joined_date = date.today()
    def set_teacher_join_date(self, join_date):
        self.__teacher_joined_date = join_date
    def get_teacher_join_date(self):
        return self.__teacher_joined_date

    """End of Done by Jason"""

    """Done by Wei Ren"""

    def add_to_cart(self, courseID):        #e.g. add_to_cart(0)
        if courseID not in self.__shoppingCart:
            self.__shoppingCart.append(courseID)
        else:
            print("Course ID", courseID, "already in shopping cart.")
    def remove_from_cart(self,courseID):
        try:
            self.__shoppingCart.remove(courseID)
        except KeyError:
            print("Course ID", courseID, "not in shopping cart.")
        except:
            print("Unexpected error.")

    def set_shoppingCart(self, shoppingCart):
        self.__shoppingCart = shoppingCart
    def get_shoppingCart(self):
        return self.__shoppingCart

    """End of Done by Wei Ren"""
