# import python standard libraries
import pathlib, json, re
from sys import exit as sysExit
from typing import Union

# import third party libraries
from argon2 import PasswordHasher, Type as Argon2Type
from dicebear import DOptions

# For ipinfo.io to get details about a user's IP address
import ipinfo

# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google SM (Secret Manager) API (Third-party libraries)
from google.cloud import secretmanager, kms

# For Google CLoud Logging API (Third-party libraries)
from google.cloud import logging as gcp_logging
from google.cloud.logging.handlers import CloudLoggingHandler

# For Google Cloud SQL API (Third-party libraries)
from google.oauth2 import service_account
from google.cloud.sql.connector import Connector as MySQLConnector

# For Google Cloud reCAPTCHA API (Third-party libraries)
from google.cloud import recaptchaenterprise_v1

# For Google Cloud Storage API (Third-party libraries)
from google.cloud import storage

class ConstantsConfigs:
    """
    This class is used to store all the constants used in the application.
    
    You can add new constants by using the add_new_constant function as well 
    or directly adding them to the class in the __init__/constructor function.
    """
    
    """------------------------ START OF DEFINING FUNCTIONS ------------------------"""

    def get_secret_payload(self, secretID:str="", versionID:str="latest", decodeSecret:bool=True) -> Union[str, bytes]:
        """
        Get the secret payload from Google Cloud Secret Manager API.
        
        Args:
        - secretID (str): The ID of the secret.
        - versionID (str): The version ID of the secret.
        - decodeSecret (bool): If true, decode the returned secret bytes payload to string type.
        
        Returns:
        - secretPayload (str|bytes): the secret payload
        """
        # construct the resource name of the secret version
        secretName = self.__SM_CLIENT.secret_version_path(self.__GOOGLE_PROJECT_ID, secretID, versionID)

        # get the secret version
        try:
            response = self.__SM_CLIENT.access_secret_version(request={"name": secretName})
        except (GoogleErrors.NotFound) as e:
            # secret version not found
            print("Error caught:")
            print(e, end="\n\n")
            return

        # return the secret payload
        secret = response.payload.data
        return secret.decode("utf-8") if (decodeSecret) else secret

    """------------------------ END OF DEFINING FUNCTIONS ------------------------"""

    """------------------------ START OF DEFINING CONSTANTS ------------------------"""

    def __init__(self):
        # Debug flag
        self.__DEBUG_MODE = True 

        # For redirecting user to the custom domain on firebase
        self.__FIREBASE_DOMAIN_REGEX = re.compile(r"^(https://coursefinity-339412\.web\.app|https://coursefinity-339412\.firebaseapp\.com)(\/.*)?$")

        # Blueprints endpoint routes
        #TODO:Integrate this with the admin console
        self.__GUEST_BLUEPRINTS = ("guestBP", "generalBP","errorBP")
        self.__USER_BLUEPRINTS = ("generalBP", "userBP", "loggedInBP", "errorBP")
        self.__ADMIN_BLUEPRINTS = ("adminBP", "generalBP", "loggedInBP", "errorBP","userBP")
        self.__SUPER_ADMIN_BLUEPRINTS = ("superAdminBP", "generalBP", "loggedInBP", "errorBP","userBP","adminBP")
        self.__TEACHER_BLUEPRINTS = ("userBP", "generalBP", "loggedInBP", "errorBP","teacherBP") # it's better to seperate the teacher and student blueprints
        # Request limit
        self.__REQUEST_LIMIT = "120 per minute"

        # For lockout policy
        self.__MAX_LOGIN_ATTEMPTS = 6

        # For Flask's session cookie
        self.__SESSION_NUM_OF_BYTES = 512
        # For invalidating sessions after x mins of inactivity
        # Inactivity in this case: No requests to the web server for x mins
        self.__SESSION_EXPIRY_INTERVALS = 60 # 60 mins/1 hr

        # Duration (in minutes) for locked accounts
        # before user can try to login again
        self.__LOCKED_ACCOUNT_DURATION = 30 # 30 mins

        # Configurations for dicebear api for user profile image options
        self.__DICEBEAR_OPTIONS = DOptions(size=250)

        # Configurations on the allowed extensions for files such as images
        self.__ALLOWED_IMAGE_EXTENSIONS = (".png", ".jfif", ".jpg", ".jpeg")
        self.__ALLOWED_VIDEO_EXTENSIONS = (".3g2", ".3gpp", ".3gp", ".asf", ".avchd", ".avi", ".flv", ".m4a", ".mkv", ".mov", ".mp4", ".mts", ".webm", ".wmv")

        # path to the root directory of the project
        self.__ROOT_FOLDER_PATH = pathlib.Path(__file__).parent.parent.parent.absolute()

        # for the config files folder
        self.__CONFIG_FOLDER_PATH = self.ROOT_FOLDER_PATH.joinpath("config_files")
        self.__CONFIG_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

        # For comparing the date on the github repo
        self.__DATE_FORMAT = "%Y-%m-%d %H:%M:%S %z"
        self.__BLACKLIST_FILEPATH = self.ROOT_FOLDER_PATH.joinpath("config_files", "ip_blacklist.txt")

        # Password regex follows OWASP's recommendations
        # https://owasp.deteact.com/cheat/cheatsheets/Authentication_Cheat_Sheet.html#password-complexity
        self.__MIN_PASSWORD_LENGTH = 8
        self.__MAX_PASSWORD_LENGTH = 128
        # Strict password regex to be used when haveibeenpwned's API is down (acts as a fallback)
        self.__STRICT_PASSWORD_REGEX = re.compile(r"""
        ^                                                                   # beginning of password
        (?!.*([A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])\1{2})    # not more than 2 identical characters in a row
        (?=.*?[a-z])                                                        # at least one lowercase letter
        (?=.*?[A-Z])                                                        # at least one uppercase letter
        (?=.*?[\d])                                                         # at least one digit
        (?=.*?[!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])                  # at least one special character
        [A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]                 # allowed characters
        {8,}                                                                # at least 8 characters long
        $                                                                   # end of password
        """, re.VERBOSE)
        # For individually test the password regex for each of the following:
        self.__TWO_REPEAT_CHAR_REGEX = re.compile(
            r"^(?!.*([A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])\1{2}).+$"
        )
        self.__LOWERCASE_REGEX = re.compile(r"[a-z]+")
        self.__UPPERCASE_REGEX = re.compile(r"[A-Z]+")
        self.__DIGIT_REGEX = re.compile(r"[\d]+")
        self.__SPECIAL_CHAR_REGEX = re.compile(r"[!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]+")
        self.__LENGTH_REGEX = re.compile(r"^.{8,}$")
        self.__ALLOWED_CHAR_REGEX = re.compile(r"^[A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]{1,}$")

        # For 2FA setup key regex to validate if the setup is a valid base32 setup key
        self.__COMPILED_2FA_REGEX_DICT = {
            32: re.compile(r"^[A-Z2-7]{32}$")
        }
        self.__TWO_FA_CODE_REGEX = re.compile(r"^\d{6}$")

        # Configured Argon2id default configurations so that it will take 
        # at least 500ms/0.5s to hash a plaintext password.
        self.__PH = PasswordHasher(
            time_cost=12,         # 12 count of iterations
            salt_len=64,          # 64 bytes salt
            hash_len=64,          # 64 bytes hash
            parallelism=12,       # 12 threads
            memory_cost=256*1024, # 256 MiB
            type=Argon2Type.ID    # using hybrids of Argon2i and Argon2d
        )
        # More helpful details on choosing the parameters for argon2id:
        # https://www.ory.sh/choose-recommended-argon2-parameters-password-hashing/#argon2s-cryptographic-password-hashing-parameters
        # https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/
        # https://argon2-cffi.readthedocs.io/en/stable/parameters.html

        # for Google Cloud API
        self.__GOOGLE_PROJECT_ID = "coursefinity-339412"

        # For the Flask secret key when retrieving the secret key
        # from Google Secret Manager API
        self.__FLASK_SECRET_KEY_NAME = "flask-secret-key"

        # For Google Secret Manager API
        self.__GOOGLE_SM_JSON_PATH = self.__CONFIG_FOLDER_PATH.joinpath("google-sm.json")
        if (not self.__GOOGLE_SM_JSON_PATH.exists()):
            print("Error: Google Secret Manager Service Account JSON file not found.")
            sysExit(1)

        # Create an authorised Google Cloud Secret Manager API service instance.
        self.__SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(filename=self.__GOOGLE_SM_JSON_PATH)

        # For ipinfo.io to get details of a IP address
        IPINFO_ACCESS_TOKEN = self.get_secret_payload(secretID="ipinfo-access-token")
        self.__IPINFO_HANDLER = ipinfo.getHandler(access_token=IPINFO_ACCESS_TOKEN)
        del IPINFO_ACCESS_TOKEN

        # For Stripe API
        self.__STRIPE_PUBLIC_KEY = "pk_test_51LD90SEQ13luXvBj7mFXNdvH08TWzZ477fvvR82HNOriieL7nj230ZhWVFjLTczJVNcDx5oKUOMZuvkkrXUXxKMS00WKMQ3hDu"
        self.__STRIPE_SECRET_KEY = self.get_secret_payload(secretID="stripe-secret")

        # For Google Cloud Logging API
        self.__LOGGING_CLIENT = gcp_logging.Client.from_service_account_info(json.loads(self.get_secret_payload(secretID="google-logging")))
        self.__LOGGING_NAME = "coursefinity-web-app"
        self.__GOOGLE_LOGGING_HANDLER = CloudLoggingHandler(self.__LOGGING_CLIENT, name=self.__LOGGING_NAME)

        # For Google GMAIL API
        self.__GOOGLE_CREDENTIALS = json.loads(self.get_secret_payload(secretID="google-credentials"))
        self.__GOOGLE_TOKEN_NAME = "google-token"

        # For Google OAuth2 login
        self.__GOOGLE_CLIENT_ID = self.GOOGLE_CREDENTIALS["web"]["client_id"]

        # For Google reCAPTCHA API
        RECAPTCHA_JSON = json.loads(self.get_secret_payload(secretID="google-recaptcha"))
        self.__RECAPTCHA_CLIENT = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient.from_service_account_info(RECAPTCHA_JSON)
        self.__COURSEFINITY_SITE_KEY = "6Lc4X8EgAAAAAHxgPuly7X-soqiIZjU6-PBbkXsw"
        del RECAPTCHA_JSON

        # For Google Key Management Service API
        self.__LOCATION_ID = "asia-southeast1"
        GOOGLE_KMS_JSON = json.loads(self.get_secret_payload(secretID="google-kms"))
        self.__KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(GOOGLE_KMS_JSON)
        del GOOGLE_KMS_JSON
        self.__PEPPER_KEY_ID = "pepper-key"
        self.__SENSITIVE_DATA_KEY_ID = "sensitive-data-key"
        self.__EC_SIGNING_KEY_ID = "signing-key"
        self.__RSA_ENCRYPTION_KEY_ID = "encrypt-decrypt-key"

        # During development, we will use software protected keys
        # which are cheaper ($0.06 per month) than keys stored in HSM ($1.00-$2.50 per month).
        # Lastly, cryptographic operations will be cheaper 
        # ($0.03 per 10k operations vs $0.03-$0.15 per 10k operations)
        # More details: https://cloud.google.com/kms/pricing
        if (self.__DEBUG_MODE):
            self.__APP_KEY_RING_ID = "dev-key-ring"
        else:
            self.__APP_KEY_RING_ID = "coursefinity"

        # For Google KMS asymmetric encryption and decryption
        self.__SESSION_COOKIE_ENCRYPTION_NAME = "rsa-session-cookie-version"
        self.__SIGNATURE_VERSION_NAME = "ec-signature-version"

        # For Google MySQL Cloud API
        self.__SQL_INSTANCE_LOCATION = "coursefinity-339412:asia-southeast1:coursefinity-mysql"
        GOOGLE_SQL_JSON = json.loads(self.get_secret_payload(secretID="google-mysql"))
        self.__SQL_CLIENT = MySQLConnector(credentials=service_account.Credentials.from_service_account_info(GOOGLE_SQL_JSON))
        del GOOGLE_SQL_JSON

        # for SQL connection configuration
        self.__DATABASE_NAME = "coursefinity"
        self.__REMOTE_SQL_SERVER_IP = self.get_secret_payload(secretID="sql-ip-address")

        # For Google Cloud Storage API
        GOOGLE_STORAGE_JSON = json.loads(self.get_secret_payload(secretID="google-storage"))
        self.__GOOGLE_STORAGE_CLIENT = storage.Client.from_service_account_info(GOOGLE_STORAGE_JSON)
        self.__PUBLIC_BUCKET_NAME = "coursefinity"
        self.__DEFAULT_CACHE_CONTROL = "public, max-age=31536000" # 1 year
        del GOOGLE_STORAGE_JSON

        # For the email CSS style
        self.__EMAIL_BUTTON_STYLE = "background-color:#4CAF50;width:min(250px,40%);border-radius:5px;color:white;padding:14px 25px;text-decoration:none;text-align:center;display:inline-block;"

    """------------------------ END OF DEFINING CONSTANTS ------------------------"""

    """------------------------ START OF DEFINING GETTERS ------------------------"""

    @property
    def DEBUG_MODE(self) -> bool:
        return self.__DEBUG_MODE

    @property
    def FIREBASE_DOMAIN_REGEX(self) -> re.Pattern[str]:
        return self.__FIREBASE_DOMAIN_REGEX

    @property
    def GUEST_BLUEPRINTS(self) -> tuple:
        return self.__GUEST_BLUEPRINTS

    @property
    def USER_BLUEPRINTS(self) -> tuple:
        return self.__USER_BLUEPRINTS

    @property
    def ADMIN_BLUEPRINTS(self) -> tuple:
        return self.__ADMIN_BLUEPRINTS

    @property
    def SUPER_ADMIN_BLUEPRINTS(self) -> tuple:
        return self.__SUPER_ADMIN_BLUEPRINTS

    @property
    def TEACHER_BLUEPRINTS(self) -> tuple:
        return self.__TEACHER_BLUEPRINTS

    @property
    def REQUEST_LIMIT(self) -> str:
        return self.__REQUEST_LIMIT

    @property
    def MAX_LOGIN_ATTEMPTS(self) -> int:
        return self.__MAX_LOGIN_ATTEMPTS

    @property
    def SESSION_NUM_OF_BYTES(self) -> int:
        return self.__SESSION_NUM_OF_BYTES

    @property
    def SESSION_EXPIRY_INTERVALS(self) -> int:
        return self.__SESSION_EXPIRY_INTERVALS

    @property
    def LOCKED_ACCOUNT_DURATION(self) -> int:
        return self.__LOCKED_ACCOUNT_DURATION

    @property
    def DICEBEAR_OPTIONS(self) -> DOptions:
        return self.__DICEBEAR_OPTIONS

    @property
    def ALLOWED_IMAGE_EXTENSIONS(self) -> tuple:
        return self.__ALLOWED_IMAGE_EXTENSIONS

    @property
    def ALLOWED_VIDEO_EXTENSIONS(self) -> tuple:
        return self.__ALLOWED_VIDEO_EXTENSIONS

    @property
    def ROOT_FOLDER_PATH(self) -> pathlib.Path:
        return self.__ROOT_FOLDER_PATH

    @property
    def CONFIG_FOLDER_PATH(self) -> pathlib.Path:
        return self.__CONFIG_FOLDER_PATH

    @property
    def DATE_FORMAT(self) -> str:
        return self.__DATE_FORMAT

    @property
    def BLACKLIST_FILEPATH(self) -> pathlib.Path:
        return self.__BLACKLIST_FILEPATH

    @property
    def MIN_PASSWORD_LENGTH(self) -> int:
        return self.__MIN_PASSWORD_LENGTH

    @property
    def MAX_PASSWORD_LENGTH(self) -> int:
        return self.__MAX_PASSWORD_LENGTH

    @property
    def STRICT_PASSWORD_REGEX(self) -> re.Pattern[str]:
        return self.__STRICT_PASSWORD_REGEX

    @property
    def TWO_REPEAT_CHAR_REGEX(self) -> re.Pattern[str]:
        return self.__TWO_REPEAT_CHAR_REGEX

    @property
    def LOWERCASE_REGEX(self) -> re.Pattern[str]:
        return self.__LOWERCASE_REGEX

    @property
    def UPPERCASE_REGEX(self) -> re.Pattern[str]:
        return self.__UPPERCASE_REGEX

    @property
    def DIGIT_REGEX(self) -> re.Pattern[str]:
        return self.__DIGIT_REGEX

    @property
    def SPECIAL_CHAR_REGEX(self) -> re.Pattern[str]:
        return self.__SPECIAL_CHAR_REGEX

    @property
    def LETTER_REGEX(self) -> re.Pattern[str]:
        return self.__LETTER_REGEX

    @property
    def LENGTH_REGEX(self) -> re.Pattern[str]:
        return self.__LENGTH_REGEX

    @property
    def ALLOWED_CHAR_REGEX(self) -> re.Pattern[str]:
        return self.__ALLOWED_CHAR_REGEX

    @property
    def COMPILED_2FA_REGEX_DICT(self) -> dict[int, re.Pattern[str]]:
        return self.__COMPILED_2FA_REGEX_DICT

    @property
    def TWO_FA_CODE_REGEX(self) -> re.Pattern[str]:
        return self.__TWO_FA_CODE_REGEX

    @property
    def PH(self) -> PasswordHasher:
        return self.__PH

    @property
    def FLASK_SECRET_KEY_NAME(self) -> str:
        return self.__FLASK_SECRET_KEY_NAME

    @property
    def GOOGLE_SM_JSON_PATH(self) -> pathlib.Path:
        return self.__GOOGLE_SM_JSON_PATH

    @property
    def SM_CLIENT(self) -> secretmanager.SecretManagerServiceClient:
        return self.__SM_CLIENT

    @property
    def GOOGLE_PROJECT_ID(self) -> str:
        return self.__GOOGLE_PROJECT_ID

    @property
    def IPINFO_HANDLER(self) -> ipinfo.Handler:
        return self.__IPINFO_HANDLER

    @property
    def STRIPE_PUBLIC_KEY(self) -> str:
        return self.__STRIPE_PUBLIC_KEY

    @property
    def STRIPE_SECRET_KEY(self) -> str:
        return self.__STRIPE_SECRET_KEY

    @property
    def LOGGING_CLIENT(self) -> gcp_logging.Client:
        return self.__LOGGING_CLIENT

    @property
    def GOOGLE_LOGGING_HANDLER(self) -> CloudLoggingHandler:
        return self.__GOOGLE_LOGGING_HANDLER

    @property
    def LOGGING_NAME(self) -> str:
        return self.__LOGGING_NAME

    @property
    def GOOGLE_CREDENTIALS(self) -> dict:
        return self.__GOOGLE_CREDENTIALS

    @property
    def GOOGLE_TOKEN_NAME(self) -> str:
        return self.__GOOGLE_TOKEN_NAME

    @property
    def GOOGLE_CLIENT_ID(self) -> str:
        return self.__GOOGLE_CLIENT_ID

    @property
    def RECAPTCHA_CLIENT(self) -> recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient:
        return self.__RECAPTCHA_CLIENT

    @property
    def RECAPTCHA_SITE_KEY(self) -> str:
        return self.__RECAPTCHA_SITE_KEY

    @property
    def COURSEFINITY_SITE_KEY(self) -> str:
        return self.__COURSEFINITY_SITE_KEY

    @property
    def LOCATION_ID(self) -> str:
        return self.__LOCATION_ID

    @property
    def KMS_CLIENT(self) -> kms.KeyManagementServiceClient:
        return self.__KMS_CLIENT

    @property
    def PEPPER_KEY_ID(self) -> str:
        return self.__PEPPER_KEY_ID

    @property
    def SENSITIVE_DATA_KEY_ID(self) -> str:
        return self.__SENSITIVE_DATA_KEY_ID

    @property
    def EC_SIGNING_KEY_ID(self) -> str:
        return self.__EC_SIGNING_KEY_ID

    @property
    def RSA_ENCRYPTION_KEY_ID(self) -> str:
        return self.__RSA_ENCRYPTION_KEY_ID

    @property
    def APP_KEY_RING_ID(self) -> str:
        return self.__APP_KEY_RING_ID

    @property
    def SIGNATURE_VERSION_NAME(self) -> str:
        return self.__SIGNATURE_VERSION_NAME

    @property
    def SESSION_COOKIE_ENCRYPTION_NAME(self) -> str:
        return self.__SESSION_COOKIE_ENCRYPTION_NAME

    @property
    def SQL_INSTANCE_LOCATION(self) -> str:
        return self.__SQL_INSTANCE_LOCATION

    @property
    def SQL_CLIENT(self) -> MySQLConnector:
        return self.__SQL_CLIENT

    @property
    def DATABASE_NAME(self) -> str:
        return self.__DATABASE_NAME

    @property
    def REMOTE_SQL_SERVER_IP(self) -> str:
        return self.__REMOTE_SQL_SERVER_IP

    @property
    def GOOGLE_STORAGE_CLIENT(self) -> storage.Client:
        return self.__GOOGLE_STORAGE_CLIENT

    @property
    def PUBLIC_BUCKET_NAME(self) -> str:
        return self.__PUBLIC_BUCKET_NAME

    @property
    def DEFAULT_CACHE_CONTROL(self) -> str:
        return self.__DEFAULT_CACHE_CONTROL

    @property
    def EMAIL_BUTTON_STYLE(self) -> str:
        return self.__EMAIL_BUTTON_STYLE

    """------------------------ END OF DEFINING GETTERS ------------------------"""

# Create an ConstantsConfigs object for other 
# python files to import instead of the class
CONSTANTS = ConstantsConfigs()

# Only allow import of the variable object 
# CONSTANTS from this file if 
# from Constants import * is used
__all__ = [
    "CONSTANTS"
]