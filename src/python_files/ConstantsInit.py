# import python standard libraries
import pathlib, json
from os import environ
from sys import exit as sysExit
from typing import Union

# import third party libraries
from argon2 import PasswordHasher
from argon2 import Type as Argon2Type
from mysql.connector.constants import ClientFlag

# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google Gmail API (Third-party libraries)
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build, Resource

# For Google SM (Secret Manager) API (Third-party libraries)
from google.cloud import secretmanager, kms

"""------------------------ START OF DEFINING FUNCTIONS ------------------------"""

def get_secret_payload(secretID:str="", versionID:str="latest", decodeSecret:bool=True) -> Union[str, bytes]:
    """
    Get the secret payload from Google Cloud Secret Manager API.
    
    Args:
    - secretID (str): The ID of the secret.
    - versionID (str): The version ID of the secret.
    - decodeSecret (bool): If true, decode the returned secret bytes payload to string type.
    
    Returns:
    - secretPayload (str): the secret payload
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

def google_init() -> Resource:
    """
    Initialise Google API by trying to authenticate with token.json
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    
    Returns:
    - Google API resource object
    """
    # If modifying these scopes, delete the file token.json.
    # Scopes details: https://developers.google.com/gmail/api/auth/scopes
    SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

    creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, SCOPES)

    # Build the Gmail service from the credentials
    gmailService = build("gmail", "v1", credentials=creds)

    return gmailService

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
PASSWORD = get_secret_payload(secretID="Password")

# For Google GMAIL API
GOOGLE_CREDENTIALS = json.loads(get_secret_payload(secretID="google-credentials"))
GOOGLE_TOKEN = json.loads(get_secret_payload(secretID="google-token"))
GOOGLE_SERVICE = google_init()

# For Google Key Management Service API
LOCATION_ID = "asia-southeast1"
GOOGLE_KMS_JSON = json.loads(get_secret_payload(secretID="google-kms"))
KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(GOOGLE_KMS_JSON)

# for SQL SSL connection
SQL_SERVER_CA = CONFIG_FOLDER_PATH.joinpath("sql-server-ca.pem")
SQL_CLIENT_CERT = CONFIG_FOLDER_PATH.joinpath("sql-client-cert.pem")
SQL_CLIENT_KEY = CONFIG_FOLDER_PATH.joinpath("sql-client-key.pem")

# Get the SQL SSL certificate from Google Cloud Secret Manager API 
# and save/overwrite it to the local file system.
_SQL_SSL_DICT = {
    "sql-server-ca": SQL_SERVER_CA,
    "sql-client-cert": SQL_CLIENT_CERT,
    "sql-client-key": SQL_CLIENT_KEY
}
for secretID, path in _SQL_SSL_DICT.items():
    with open(path, "w") as f:
        f.write(get_secret_payload(secretID=secretID))
del _SQL_SSL_DICT

# for SQL connection configuration
DATABASE_NAME = "coursefinity"
REMOTE_SQL_SERVER_IP = get_secret_payload(secretID="SQL-IP-Address")
REMOTE_SQL_SERVER_PASS = PASSWORD

LOCAL_SQL_SERVER_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": environ["LOCAL_SQL_PASS"]
}
REMOTE_SQL_SERVER_CONFIG = {
    "host": REMOTE_SQL_SERVER_IP, # Google Cloud SQL Public address
    "user": "root",
    "password": REMOTE_SQL_SERVER_PASS,
    "client_flags": [ClientFlag.SSL],
    "ssl_ca": str(SQL_SERVER_CA),
    "ssl_cert": str(SQL_CLIENT_CERT),
    "ssl_key": str(SQL_CLIENT_KEY)
}

"""------------------------ END OF DEFINING CONSTANTS ------------------------"""

"""------------------------ START OF VERIFYING CONSTANTS ------------------------"""

# Do some checks that all the necessary file paths exists 
_ALL_PATH_LIST = [
    SQL_SERVER_CA,
    SQL_CLIENT_CERT,
    SQL_CLIENT_KEY
]
if (not all([path.exists() for path in _ALL_PATH_LIST])):
    raise FileNotFoundError("Some files are missing. Please ensure that all the files are in the correct folder!")

del _ALL_PATH_LIST

"""------------------------ END OF VERIFYING CONSTANTS ------------------------"""