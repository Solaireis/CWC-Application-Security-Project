from argon2 import PasswordHasher

# Done by Jason

# helpful resources: 
# https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html
# https://lindevs.com/generate-argon2id-password-hash-using-python/
# https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html
# https://stackoverflow.com/questions/58431973/argon2-library-that-hashes-passwords-without-a-secret-and-with-a-random-salt-tha

class User:
    def __init__(self, user_id, username, email, password, acc_type, status):
        self.__user_id = user_id
        self.__username = username
        self.__email = email
        self.__password = PasswordHasher().hash(password) # password is hashed using argon2
        self.__acc_type = acc_type
        self.__status = status
        self.__profile_image = ""
        self.__otp_setup_key = ""

    def set_user_id(self, user_id):
        self.__user_id = user_id
    def get_user_id(self):
        return self.__user_id

    def set_username(self, username):
        self.__username = username
    def get_username(self):
        return self.__username

    def set_email(self, email):
        self.__email = email
    def get_email(self):
        return self.__email

    def set_password(self, password):
        self.__password = PasswordHasher().hash(password) # password is hashed using argon2
    def set_password_hash(self, password):
        self.__password = password # password is an argon2 hash
    def get_password(self):
        return self.__password

    def set_acc_type(self, acc_type):
        self.__acc_type = acc_type
    def get_acc_type(self):
        return self.__acc_type

    def set_status(self, status):
        self.__status = status
    def get_status(self):
        return self.__status

    def set_profile_image(self, imagePath):
        self.__profile_image = imagePath
    def get_profile_image(self):
        return self.__profile_image

    # things to note, argon2 by default will generate a random salt and use 65536KB of memory and time is 3 iterations, and 4 degrees of parallelism when hashing
    # argon2 is able to extract the random salt from the hash when comparing the hash with a plaintext password which is more secure than setting a salt of your own.
    # minimum requirement as of OWASP; Use Argon2id with a minimum configuration of 15 MiB of memory (15728KB), an iteration count of 2, and 1 degree of parallelism.
    # OWASP website: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    
    # for verifying a hashed value with a plaintext to see if it matches
    def verify_password(self, password):
        # try and except as argon2 will raise an exception if the hashes are not matched
        try:
            return PasswordHasher().verify(self.__password, password) # will return True if both the hash matches
        except:
            return False

    def set_otp_setup_key(self, setupKey):
        self.__otp_setup_key = setupKey
    def get_otp_setup_key(self):
        return self.__otp_setup_key