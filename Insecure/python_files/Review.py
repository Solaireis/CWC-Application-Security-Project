# Done by Wei Ren
from datetime import datetime

class Review():
    def __init__(self, userID, title, comment, rating):
        self.__userID= userID
        self.__title = title
        self.__comment = comment
        self.__rating = int(rating)
        self.__review_time = str(datetime.now().strftime("%d/%m/%Y, %H:%M:%S (UTC +8)"))

    def set_userID(self, userID):
        self.__userID = userID
    def get_userID(self):
        return self.__userID

    def set_title(self, title):
        self.__title = title
    def get_title(self):
        return self.__title

    def set_comment(self, comment):
        self.__comment = comment
    def get_comment(self):
        return self.__comment

    def set_rating(self, rating):
        self.__rating = rating
    def get_rating(self):
        return self.__rating

    def update_review_time(self):
        self.__review_time = str(datetime.now().strftime("%d/%m/%Y, %H:%M:%S (UTC +8)"))
    def get_review_time(self):
        return self.__review_time