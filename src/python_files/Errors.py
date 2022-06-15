class ReusedUsernameError(Exception):
    """
    Raised when a user tries to create an account with a username that is already in use or
    when changing their username to a username that is already in use.
    """

class EmailAlreadyInUseError(Exception):
    """
    Raised when a user tries to create an account with an email that is already in use or
    when changing their email to an email that is already in use.
    """

class SameAsOldEmailError(Exception):
    """
    Raised when a user tries to change their email to the email they are already using.
    """

class IncorrectPwdError(Exception):
    """
    Raised when a user tries to login with an incorrect password.
    """

class EmailDoesNotExistError(Exception):
    """
    Raised when a user tries to login with an email that does not exist.
    """

class ReusedPwdError(Exception):
    """
    Raised if the password to be changed is the same as the new password.
    """

class ChangePwdError(Exception):
    """
    Raised if the user tries to change their password but provided an incorrect old password.
    """

class PwdTooShortError(Exception):
    """
    Raised if the password is too short (less than 8 characters).
    
    As recommended by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls), the password should be at least 8 characters long.
    """

class PwdTooLongError(Exception):
    """
    Raised if the password is too long.

    Reason: 
        - Due to limitations of the password hashing algorithm, the password cannot be longer than
        around 64 characters.
        - Since argon2 uses a default length of 16 for its salt, the max length of the password I've
        set is 48 characters.

    More details:
        https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls
    """

class PwdTooWeakError(Exception):
    """
    Raised if the password is too weak as it has been found in haveibeenpwned's api databases of
    leaked passwords in the dark web caused by data breaches
    """

class CardDoesNotExistError(Exception):
    """
    Raised if the user tries to do CRUD operations on their credit card but their credit card does not exist.
    """

class HaveibeenpwnedRequestError(Exception):
    """
    Raised if the user tries to check their password against the HaveIBeenPwned database but the request
    to the API failed (status code is not 200 or 429).
    """

class IsAlreadyTeacherError(Exception):
    """
    Raised if the user tries to become a teacher even though they are already a teacher.
    """