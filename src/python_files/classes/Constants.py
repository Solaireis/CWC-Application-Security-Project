# import python standard libraries
import pathlib, json, re
from sys import exit as sysExit
from typing import Union
from dataclasses import dataclass, field

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

# TODO: Change debug mode below ONLY!
DEBUG_MODE = True

@dataclass(frozen=True, repr=False)
class Constants:
    """This dataclass is used to store all the constants used in the application."""
    # Debug flag
    DEBUG_MODE: bool = DEBUG_MODE 

    # For redirecting user to the custom domain which is protected by Cloudflare
    CUSTOM_DOMAIN_REGEX: re.Pattern[str] = re.compile(r"^(https://coursefinity\.social)(\/.*)?$")

    # Follows the MySQL columns in the database
    BLUEPRINT_ORDER_TUPLE: tuple = ("guestBP", "generalBP", "adminBP", "loggedInBP", "errorBP", "teacherBP", "userBP", "superAdminBP")
    ROLE_NAME_ORDER_TUPLE: tuple = ("Student", "Teacher", "Admin", "SuperAdmin", "Guest")

    # Request limit
    REQUEST_LIMIT: str = "120 per minute"

    # For lockout policy
    MAX_LOGIN_ATTEMPTS: int = 6

    # For removing session identifiers that has no activity for more than x mins 
    # (Expiry date will be updated per request to the web application)
    SESSION_EXPIRY_INTERVALS: int = 90 # 1 hour and 30 mins

    # Duration (in minutes) for locked accounts
    # before user can try to login again
    LOCKED_ACCOUNT_DURATION: int = 30 # 30 mins

    # Configurations for dicebear api for user profile image options
    DICEBEAR_OPTIONS: DOptions = field(default_factory=lambda: DOptions(size=250))

    # Configurations on the allowed extensions for files such as images
    ALLOWED_IMAGE_EXTENSIONS: tuple = (".png", ".jfif", ".jpg", ".jpeg")
    ALLOWED_VIDEO_EXTENSIONS: tuple = (".3g2", ".3gpp", ".3gp", ".asf", ".avchd", ".avi", ".flv", ".m4a", ".mkv", ".mov", ".mp4", ".mts", ".webm", ".wmv")

    # path to the root directory of the project
    ROOT_FOLDER_PATH: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute()

    # for the config files folder
    CONFIG_FOLDER_PATH: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute().joinpath("config_files")

    # Password regex follows OWASP's recommendations
    # https://owasp.deteact.com/cheat/cheatsheets/Authentication_Cheat_Sheet.html#password-complexity
    MIN_PASSWORD_LENGTH: int = 8
    MAX_PASSWORD_LENGTH: int = 64 # To prevent long password denial of service
    # Strict password regex to be used when haveibeenpwned's API is down (acts as a fallback)
    STRICT_PASSWORD_REGEX: re.Pattern[str] = re.compile(r"""
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
    TWO_REPEAT_CHAR_REGEX: re.Pattern[str] = re.compile(
        r"^(?!.*([A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])\1{2}).+$"
    )
    LOWERCASE_REGEX: re.Pattern[str] = re.compile(r"[a-z]+")
    UPPERCASE_REGEX: re.Pattern[str] = re.compile(r"[A-Z]+")
    DIGIT_REGEX: re.Pattern[str] = re.compile(r"[\d]+")
    SPECIAL_CHAR_REGEX: re.Pattern[str] = re.compile(r"[!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]+")
    LENGTH_REGEX: re.Pattern[str] = re.compile(r"^.{8,}$")
    ALLOWED_CHAR_REGEX: re.Pattern[str] = re.compile(r"^[A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]{1,}$")

    # For 2FA setup key regex to validate if the setup key is a valid base32 string and if the TOTP is 6 digits
    TWENTY_BYTES_2FA_REGEX: re.Pattern[str] = re.compile(r"^[A-Z2-7]{32}$")
    TWO_FA_CODE_REGEX: re.Pattern[str] = re.compile(r"^\d{6}$")

    # Configured Argon2id default configurations so that it will take 
    # at least +-200ms/0.2s to hash a plaintext password 
    # on a decent Desktop PC (Ryzen 5 3600X + RTX2070 Super)
    # i.e. around 5 hashes per minute
    PH: PasswordHasher = PasswordHasher(
        time_cost=8,          # 8 count of iterations
        salt_len=64,          # 64 bytes salt
        hash_len=64,          # 64 bytes hash
        parallelism=16,       # 16 threads
        memory_cost=128*1024, # 128MiB
        type=Argon2Type.ID    # using hybrids of Argon2i and Argon2d
    )
    # More helpful details on choosing the parameters for argon2id:
    # https://www.ory.sh/choose-recommended-argon2-parameters-password-hashing/#argon2s-cryptographic-password-hashing-parameters
    # https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/
    # https://argon2-cffi.readthedocs.io/en/stable/parameters.html

    # for Google Cloud API
    GOOGLE_PROJECT_ID: str = "coursefinity-339412"

    # For the Flask secret key when retrieving the secret key
    # from Google Secret Manager API
    FLASK_SECRET_KEY_NAME: str = "flask-secret-key"
    FLASK_SALT_KEY_NAME: str = "flask-session-salt"

    # For Flask session cookie
    SESSION_NUM_OF_BYTES: int = 512
    SALT_NUM_OF_BYTES: int = 64

    # For Stripe API
    STRIPE_PUBLIC_KEY: str = "pk_test_51LD90SEQ13luXvBj7mFXNdvH08TWzZ477fvvR82HNOriieL7nj230ZhWVFjLTczJVNcDx5oKUOMZuvkkrXUXxKMS00WKMQ3hDu"

    # For Google Cloud Logging API
    LOGGING_NAME: str = "coursefinity-web-app"
    LOGGING_SEVERITY_TUPLE: tuple = ("DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")

    # For Google Gmail API
    GOOGLE_TOKEN_NAME: str = "google-token"

    # For Google reCAPTCHA API
    COURSEFINITY_SITE_KEY: str = "6Lc4X8EgAAAAAHxgPuly7X-soqiIZjU6-PBbkXsw"

    # For Google Key Management Service API
    LOCATION_ID: str = "asia-southeast1"

    # During development, we will use software protected keys
    # which are cheaper ($0.06 per month) than keys stored in HSM ($1.00-$2.50 per month).
    # Lastly, cryptographic operations will be cheaper 
    # ($0.03 per 10k operations vs $0.03-$0.15 per 10k operations)
    # More details: https://cloud.google.com/kms/pricing
    APP_KEY_RING_ID: str = "dev-key-ring" if (DEBUG_MODE) else "coursefinity"
    AVAILABLE_KEY_RINGS: tuple = ("dev-key-ring") if (DEBUG_MODE) else ("coursefinity")

    # For encrypting data in the database
    PEPPER_KEY_ID: str = "pepper-key"
    SENSITIVE_DATA_KEY_ID: str = "sensitive-data-key"

    # For encrypting data that will be shared with the client (e.g. the JWT signature)
    COOKIE_ENCRYPTION_KEY_ID: str = "cookie-key"
    EC_SIGNING_KEY_ID: str = "signing-key"
    SIGNATURE_VERSION_NAME: str = "ec-signature-version"
    AVAILABLE_KEY_IDS: tuple = ("cookie-key", "signing-key")

    # For Google MySQL Cloud API
    SQL_INSTANCE_LOCATION: str = "coursefinity-339412:asia-southeast1:coursefinity-mysql"

    # for SQL connection configuration
    DATABASE_NAME: str = "coursefinity"

    # For Google Cloud Storage API
    PUBLIC_BUCKET_NAME: str = "coursefinity"
    COURSE_VIDEOS_BUCKET_NAME: str = "coursefinity-videos"
    GOOGLE_STORAGE_URL_REGEX: re.Pattern[str] = re.compile(
        r"^https:\/\/storage\.cloud\.google\.com\/[a-zA-Z0-9-_ ]+\/.+$"
    )
    DEFAULT_CACHE_CONTROL: str = "public, max-age=31536000" # 1 year

    # For the email CSS style
    EMAIL_BUTTON_STYLE: str = "background-color:#4CAF50;width:min(250px,40%);border-radius:5px;color:white;padding:14px 25px;text-decoration:none;text-align:center;display:inline-block;"

    # For checking if the url is a valid url
    # Used for user's input in the markdown content for course description redirect confirmation
    # Regex from https://stackoverflow.com/questions/3809401/what-is-a-good-regular-expression-to-match-a-url
    URL_REGEX: re.Pattern[str] = re.compile(
        r"^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$"
    )

    # For redirect confirmation url (since a link can be from a user's input)
    REDIRECT_CONFIRMATION_URL: str = "/redirect"
    REDIRECT_CONFIRMATION_PARAM_NAME: str = "url"

    # For formatting dates
    DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S %z"

    # Course category table for converting course category ID to a more user-friendly name
    CATEGORY_TABLE: dict[str, str] = field(default_factory=lambda: {
        "Programming": "Development - Programming",
        "Web_Development": "Development - Web Development",
        "Game_Development": "Development - Game Development",
        "Mobile_App_Development": "Development - Mobile App Development",
        "Software_Development": "Development - Software Development",
        "Other_Development": "Development - Other Development",
        "Entrepreneurship": "Business - Entrepreneurship",
        "Project_Management": "Business - Project Management",
        "BI_Analytics": "Business - Business Intelligence & Analytics",
        "Business_Strategy": "Business - Business Strategy",
        "Other_Business": "Business - Other Business",
        "3D_Modelling": "Design - 3D Modelling",
        "Animation": "Design - Animation",
        "UX_Design": "Design - UX Design",
        "Design_Tools": "Design - Design Tools",
        "Other_Design": "Design - Other Design",
        "Digital_Photography": "Photography/Videography - Digital Photography",
        "Photography_Tools": "Photography/Videography - Photography Tools",
        "Video_Production": "Photography/Videography - Video Production",
        "Video_Design_Tools": "Photography/Videography - Video Design Tools",
        "Other_Photography_Videography": "Photography/Videography - Other Photography/Videography",
        "Science": "Academics - Science",
        "Math": "Academics - Math",
        "Language": "Academics - Language",
        "Test_Prep": "Academics - Test Prep",
        "Other_Academics": "Academics - Other Academics"
    })

    def __post_init__(self) -> None:
        """Called after the dataclass is initialised."""
        # Create the config files folder
        self.CONFIG_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

# Create the initialised Constants object for other 
# python files to import instead of the class
CONSTANTS = Constants()

class SecretConstants:
    """
    This class is used to store all the SECRET constants used in the application.

    The secret constants are retrieved from Google Cloud Platform Secret Manager API.
    """

    """------------------------ START OF FUNCTION FOR GETTING DATA FROM GCP SECRET MANAGER API ------------------------"""

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
        secretName = self.__SM_CLIENT.secret_version_path(CONSTANTS.GOOGLE_PROJECT_ID, secretID, versionID)

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

    """------------------------ END OF FUNCTION FOR GETTING DATA FROM GCP SECRET MANAGER API ------------------------"""

    """----------------------------------------- START OF DEFINING CONSTANTS -----------------------------------------"""

    def __init__(self):
        # For Google Secret Manager API
        GOOGLE_SM_JSON_PATH = CONSTANTS.CONFIG_FOLDER_PATH.joinpath("google-sm.json")
        if (not GOOGLE_SM_JSON_PATH.exists() or not GOOGLE_SM_JSON_PATH.is_file()):
            print("Error: Google Secret Manager Service Account JSON file not found.")
            sysExit(1)

        # Create an authorised Google Cloud Secret Manager API service instance.
        self.__SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(filename=GOOGLE_SM_JSON_PATH)
        del GOOGLE_SM_JSON_PATH

        # For ipinfo.io to get details of a IP address
        self.__IPINFO_HANDLER = ipinfo.getHandler(
            access_token=self.get_secret_payload(secretID="ipinfo-access-token")
        )

        # For Stripe API
        self.__STRIPE_SECRET_KEY = self.get_secret_payload(secretID="stripe-secret")

        # For Google Cloud Logging API
        self.__LOGGING_CLIENT = gcp_logging.Client.from_service_account_info(json.loads(self.get_secret_payload(secretID="google-logging")))
        self.__GOOGLE_LOGGING_HANDLER = CloudLoggingHandler(self.__LOGGING_CLIENT, name=CONSTANTS.LOGGING_NAME)

        # For Google Gmail API
        self.__GOOGLE_CREDENTIALS = json.loads(self.get_secret_payload(secretID="google-credentials"))

        # For Google reCAPTCHA API
        self.__RECAPTCHA_CLIENT = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient.from_service_account_info(
            json.loads(self.get_secret_payload(secretID="google-recaptcha"))
        )

        # For Google Key Management Service API
        self.__KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(
            json.loads(self.get_secret_payload(secretID="google-kms"))
        )

        # For Google MySQL Cloud API
        self.__SQL_CLIENT = MySQLConnector(
            credentials=service_account.Credentials.from_service_account_info(
                json.loads(self.get_secret_payload(secretID="google-mysql"))
            )
        )

        # For Google Cloud Storage API
        self.__GOOGLE_STORAGE_CLIENT = storage.Client.from_service_account_info(
            json.loads(self.get_secret_payload(secretID="google-storage"))
        )

    """----------------------------------------- END OF DEFINING CONSTANTS -----------------------------------------"""

    """----------------------------------------- START OF DEFINING GETTERS -----------------------------------------"""

    @property
    def SM_CLIENT(self) -> secretmanager.SecretManagerServiceClient:
        return self.__SM_CLIENT

    @property
    def IPINFO_HANDLER(self) -> ipinfo.Handler:
        return self.__IPINFO_HANDLER

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
    def GOOGLE_CREDENTIALS(self) -> dict:
        return self.__GOOGLE_CREDENTIALS

    @property
    def RECAPTCHA_CLIENT(self) -> recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient:
        return self.__RECAPTCHA_CLIENT

    @property
    def KMS_CLIENT(self) -> kms.KeyManagementServiceClient:
        return self.__KMS_CLIENT

    @property
    def SQL_CLIENT(self) -> MySQLConnector:
        return self.__SQL_CLIENT

    @property
    def GOOGLE_STORAGE_CLIENT(self) -> storage.Client:
        return self.__GOOGLE_STORAGE_CLIENT

    """----------------------------------------- END OF DEFINING GETTERS -----------------------------------------"""

# Create the initialised SecretConstants object for other 
# python files to import instead of the class
SECRET_CONSTANTS = SecretConstants()

# Only allow import of the variable object 
# CONSTANTS from this file if 
# from Constants import * is used
__all__ = [
    "SECRET_CONSTANTS",
    "CONSTANTS"
]