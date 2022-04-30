from .User import User

# Done by Jason

class Admin(User):
    def __init__(self, user_id, username, email, password):
        super().__init__(user_id, username, email, password, "Admin", "Active")