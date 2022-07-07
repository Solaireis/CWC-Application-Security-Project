class UserDoesNotExist(Exception):
    """
    Raised when a user does not exist.
    """

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

class EmailNotVerifiedError(Exception):
    """
    Raised when a user tries to login with an email that has not been verified.
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
        - Due to limitations of the password hashing algorithm, the password cannot be too long.
        - Set the limit to 128 characters as defined in Constants_Init.py
    
    More details:
        https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls
    """

class PwdTooWeakError(Exception):
    """
    Raised if the password is too weak as it has been found in haveibeenpwned's api databases of
    leaked passwords in the dark web caused by data breaches
    
    It is also raised if the password does not meet the minimum complexity requirements.
    """

class haveibeenpwnedAPIDownError(Exception):
    """
    Raised if the haveibeenpwned API is down.
    """

class CardDoesNotExistError(Exception):
    """
    Raised if the user tries to do CRUD operations on their credit card but their credit card does not exist.
    """

class IsAlreadyTeacherError(Exception):
    """
    Raised if the user tries to become a teacher even though they are already a teacher.
    """

class AccountLockedError(Exception):
    """
    Raised if the user tries to login but their account is locked.

    Reasons for locked account: 
        - Too many failed login attempts. (> 10 attempts)
    """

class No2FATokenError(Exception):
    """
    Raised if the user tries to login but they have not enabled 2FA.
    """

class CRC32ChecksumError(Exception):
    """
    Raised if the CRC32C checksum does not match during decryption.
    """

class RSACiphertextIsNotValidFormatError(Exception):
    """
    Raised if the ciphertext is not the correct format.
    
    Must be a dictionary containing the following keys:
    - {\n
        "header": {
            "key_ring_id" : key ring name used,
            "key_id" : key name used,
            "version_id" : key version used
        },
        "ciphertext": the encrypted plaintext in bytes
    }
    """

class CiphertextIsNotBytesError(Exception):
    """
    Raised if the ciphertext is not bytes.
    """

class DecryptionError(Exception):
    """
    Raised if the decryption fails.
    """

class InvalidProfilePictureError(Exception):
    """
    Raised if the profile image is not a valid image.
    """

class UserIsUsingOauth2Error(Exception):
    """
    Raised if the user tries to login but is not using Google OAuth2 to login.
    """

class LoginFromNewIpAddressError(Exception):
    """
    Raised if the user tries to login from a new IP address.
    """

class InvalidRecaptchaTokenError(Exception):
    """
    Raised if the user tries to login but the recaptcha token is invalid.
    """

class InvalidRecaptchaActionError(Exception):
    """
    Raised if the user tries to login but the recaptcha action is invalid.
    """

class EncryptionError(Exception):
    """
    Raised if the encryption fails.
    """

class UploadFailedError(Exception):
    """
    Raised if the uploading of files to Google Cloud Platform Storage API fails.
    """