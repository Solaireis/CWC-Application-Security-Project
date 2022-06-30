# import python standard libraries
import pathlib, json
from os import environ
from sys import exit as sysExit
from typing import Any, Union

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
from google.cloud import logging as g_logging

# For Google Cloud SQL API (Third-party libraries)
from google.oauth2 import service_account
from google.cloud.sql.connector import Connector as MySQLConnector

# For Google Cloud reCAPTCHA API (Third-party libraries)
from google.cloud import recaptchaenterprise_v1

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
        secretName = self.SM_CLIENT.secret_version_path(self.GOOGLE_PROJECT_ID, secretID, versionID)

        # get the secret version
        try:
            response = self.SM_CLIENT.access_secret_version(request={"name": secretName})
        except (GoogleErrors.NotFound) as e:
            # secret version not found
            print("Error caught:")
            print(e, end="\n\n")
            return

        # return the secret payload
        secret = response.payload.data
        return secret.decode("utf-8") if (decodeSecret) else secret

    def add_new_constant(self, constantName:str, constantValue:Any) -> None:
        """
        Add a new constant (Never use this function with inputs from end users!)
        """
        setattr(self, constantName, constantValue)

    """------------------------ END OF DEFINING FUNCTIONS ------------------------"""

    """------------------------ START OF DEFINING CONSTANTS ------------------------"""

    def __init__(self):
        # Debug flag
        self.DEBUG_MODE = True 

        # For hashing passwords
        self.MAX_PASSWORD_LENGTH = 128

        # For lockout policy
        self.MAX_LOGIN_ATTEMPTS = 6

        # For invalidating sessions after x mins of inactivity
        # Inactivity in this case: No requests to the web server for x mins
        self.SESSION_EXPIRY_INTERVALS = 30 # 30 mins

        # Duration (in minutes) for locked accounts
        # before user can try to login again
        self.LOCKED_ACCOUNT_DURATION = 30 # 30 mins

        # Configurations for dicebear api for user profile image options
        self.DICEBEAR_OPTIONS = DOptions(size=250)

        # Configurations on the allowed image extensions
        self.ALLOWED_IMAGE_EXTENSIONS = ("png", "jpg", "jpeg")

        # Configured Argon2id default configurations so that it will take 
        # at least 500ms/0.5s to hash a plaintext password.
        self.PH = PasswordHasher(
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

        # For the Flask secret key when retrieving the secret key
        # from Google Secret Manager API
        self.FLASK_SECRET_KEY_NAME = "flask-secret-key"

        # path to the root directory of the project
        self.ROOT_FOLDER_PATH = pathlib.Path(__file__).parent.parent.absolute()

        # for the config files folder
        self.CONFIG_FOLDER_PATH = self.ROOT_FOLDER_PATH.joinpath("config_files")

        # For Google Secret Manager API
        self.GOOGLE_SM_JSON_PATH = self.CONFIG_FOLDER_PATH.joinpath("google-sm.json")
        if (not self.GOOGLE_SM_JSON_PATH.exists()):
            print("Error: Google Secret Manager Service Account JSON file not found.")
            sysExit(1)

        # Create an authorised Google Cloud Secret Manager API service instance.
        self.SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(filename=self.GOOGLE_SM_JSON_PATH)

        # for Google Cloud API
        self.GOOGLE_PROJECT_ID = "coursefinity-339412"

        # For ipinfo.io to get details of a IP address
        IPINFO_ACCESS_TOKEN = self.get_secret_payload(secretID="ipinfo-access-token")
        self.IPINFO_HANDLER = ipinfo.getHandler(access_token=IPINFO_ACCESS_TOKEN)
        del IPINFO_ACCESS_TOKEN

        # For Stripe API
        self.STRIPE_PUBLIC_KEY = "pk_test_51LD90SEQ13luXvBj7mFXNdvH08TWzZ477fvvR82HNOriieL7nj230ZhWVFjLTczJVNcDx5oKUOMZuvkkrXUXxKMS00WKMQ3hDu"
        self.STRIPE_SECRET_KEY = self.get_secret_payload(secretID="stripe-secret")

        # For Google Cloud Logging API
        self.LOGGING_CLIENT = g_logging.Client.from_service_account_info(json.loads(self.get_secret_payload(secretID="google-logging")))
        self.LOGGING_NAME = "coursefinity-web-app"

        # For Google GMAIL API
        self.GOOGLE_CREDENTIALS = json.loads(self.get_secret_payload(secretID="google-credentials"))

        # For Google reCAPTCHA API
        RECAPTCHA_JSON = json.loads(self.get_secret_payload(secretID="google-recaptcha"))
        self.RECAPTCHA_CLIENT = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient.from_service_account_info(RECAPTCHA_JSON)
        self.LOGIN_SITE_KEY = "6LfpqZcgAAAAAC7RH7qroayHutXeXkpLuKY5iV6a"
        self.SIGNUP_SITE_KEY = "6LfItpcgAAAAAL2DVlCIG-nKm8_ctRZKOuCfMo1B"
        del RECAPTCHA_JSON

        # For Google Key Management Service API
        self.LOCATION_ID = "asia-southeast1"
        GOOGLE_KMS_JSON = json.loads(self.get_secret_payload(secretID="google-kms"))
        self.KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(GOOGLE_KMS_JSON)
        del GOOGLE_KMS_JSON
        self.PEPPER_KEY_ID = "pepper-key"
        self.SENSITIVE_DATA_KEY_ID = "sensitive-data-key"
        self.EC_SIGNING_KEY_ID = "signing-key"
        self.APP_KEY_RING_ID = "coursefinity"

        # For Google MySQL Cloud API
        self.SQL_INSTANCE_LOCATION = "coursefinity-339412:asia-southeast1:coursefinity-mysql"
        GOOGLE_SQL_JSON = json.loads(self.get_secret_payload(secretID="google-mysql"))
        self.SQL_CLIENT = MySQLConnector(credentials=service_account.Credentials.from_service_account_info(GOOGLE_SQL_JSON))
        del GOOGLE_SQL_JSON

        # for SQL connection configuration
        self.DATABASE_NAME = "coursefinity"
        self.REMOTE_SQL_SERVER_IP = self.get_secret_payload(secretID="sql-ip-address")

        self.LOCAL_SQL_SERVER_CONFIG = {
            "host": "localhost",
            "user": "root",
            "password": environ.get("LOCAL_SQL_PASS")
        }

    """------------------------ END OF DEFINING CONSTANTS ------------------------"""

# Create an ConstantsConfigs object for other 
# python files to import instead of the class
CONSTANTS = ConstantsConfigs()

# Only allow import of the variable object 
# CONSTANTS from this file if 
# from Constants import * is used
__all__ = [
    "CONSTANTS"
]