# Done by Wei Ren

class Cashout():
    def __init__(self, cashoutID, time, amount, cashoutType, cashoutContact):
        self.__cashoutID = cashoutID
        self.__time = time
        self.__amount = amount
        self.__cashoutType = cashoutType
        self.__cashoutContact = cashoutContact

    def get_cashoutID(self):
        return self.__cashoutID
    def set_cashoutID(self, cashoutID):
        self.__cashoutID = cashoutID

    def get_time(self):
        return self.__time
    def set_time(self, time):
        self.__time = time

    def get_amount(self):
        return self.__amount
    def set_amount(self, amount):
        self.__amount = amount

    def get_cashoutType(self):
        return self.__cashoutType
    def set_cashoutType(self):
        return self.__cashoutType

    def get_cashoutContact(self):
        return self.__cashoutContact
    def set_cashoutContact(self, cashoutContact):
        self.__cashoutContact = cashoutContact