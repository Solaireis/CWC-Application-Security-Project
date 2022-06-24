# import python standard libraries
import pathlib, json
from os import environ
from sys import exit as sysExit
from typing import Union

# import third party libraries
from argon2 import PasswordHasher, Type as Argon2Type

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

"""------------------------ START OF DEFINING FUNCTIONS ------------------------"""

def get_secret_payload(secretID:str="", versionID:str="latest", decodeSecret:bool=True) -> Union[str, bytes]:
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
    secretName = SM_CLIENT.secret_version_path(GOOGLE_PROJECT_ID, secretID, versionID)

    # get the secret version
    try:
        response = SM_CLIENT.access_secret_version(request={"name": secretName})
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

# Debug flag
DEBUG_MODE = True 

# For hashing passwords
MAX_PASSWORD_LENGTH = 128

# Configured Argon2id default configurations so that it will take 
# at least 500ms/0.5s to hash a plaintext password.
PH = PasswordHasher(
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
FLASK_SECRET_KEY_NAME = "flask-secret-key"

# path to the root directory of the project
ROOT_FOLDER_PATH = pathlib.Path(__file__).parent.parent.absolute()

# for the config files folder
CONFIG_FOLDER_PATH = ROOT_FOLDER_PATH.joinpath("config_files")
CONFIG_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

# For Google Secret Manager API
GOOGLE_SM_JSON_PATH = CONFIG_FOLDER_PATH.joinpath("google-sm.json")
if (not GOOGLE_SM_JSON_PATH.exists()):
    print("Error: Google Secret Manager Service Account JSON file not found.")
    sysExit(1)

# Create an authorised Google Cloud Secret Manager API service instance.
SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(filename=GOOGLE_SM_JSON_PATH)

# for Google Cloud API
GOOGLE_PROJECT_ID = "coursefinity-339412"

# Password
# PASSWORD = get_secret_payload(secretID="Password")

# For Stripe API
STRIPE_PUBLIC_KEY = "pk_test_51LD90SEQ13luXvBj7mFXNdvH08TWzZ477fvvR82HNOriieL7nj230ZhWVFjLTczJVNcDx5oKUOMZuvkkrXUXxKMS00WKMQ3hDu"
STRIPE_SECRET_KEY = get_secret_payload(secretID="stripe-secret")

# For Google Cloud Logging API
LOGGING_CLIENT = g_logging.Client.from_service_account_info(json.loads(get_secret_payload(secretID="google-logging")))

# For Google GMAIL API
GOOGLE_CREDENTIALS = json.loads(get_secret_payload(secretID="google-credentials"))

# For Google reCAPTCHA API
RECAPTCHA_JSON = json.loads(get_secret_payload(secretID="google-recaptcha"))
RECAPTCHA_CLIENT = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient.from_service_account_info(RECAPTCHA_JSON)
LOGIN_SITE_KEY = "6LfpqZcgAAAAAC7RH7qroayHutXeXkpLuKY5iV6a"
SIGNUP_SITE_KEY = "6LfItpcgAAAAAL2DVlCIG-nKm8_ctRZKOuCfMo1B"

# For Google Key Management Service API
LOCATION_ID = "asia-southeast1"
GOOGLE_KMS_JSON = json.loads(get_secret_payload(secretID="google-kms"))
KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(GOOGLE_KMS_JSON)

# For Google MySQL Cloud API
SQL_INSTANCE_LOCATION = "coursefinity-339412:asia-southeast1:coursefinity-mysql"
GOOGLE_SQL_JSON = json.loads(get_secret_payload(secretID="google-mysql"))
SQL_CLIENT = MySQLConnector(credentials=service_account.Credentials.from_service_account_info(GOOGLE_SQL_JSON))

# for SQL connection configuration
DATABASE_NAME = "coursefinity"
REMOTE_SQL_SERVER_IP = get_secret_payload(secretID="sql-ip-address")

LOCAL_SQL_SERVER_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": environ["LOCAL_SQL_PASS"]
}

"""------------------------ END OF DEFINING CONSTANTS ------------------------"""