# import python standard libraries
import pathlib, json
from os import environ
from sys import exit as sysExit
from typing import Union

# import third party libraries
from mysql.connector.constants import ClientFlag

# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google SM (Secret Manager) API (Third-party libraries)
from google.cloud import secretmanager

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

"""------------------------ END OF DEFINING FUNCTIONS ------------------------"""

"""------------------------ START OF DEFINING CONSTANTS ------------------------"""

# Debug flag
DEBUG_MODE = True 

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

# For Google Key Management Service API
GOOGLE_KMS_JSON = json.loads(get_secret_payload(secretID="google-kms"))

# for SQL SSL connection
SQL_SERVER_CA = CONFIG_FOLDER_PATH.joinpath("sql-server-ca.pem")
SQL_CLIENT_CERT = CONFIG_FOLDER_PATH.joinpath("sql-client-cert.pem")
SQL_CLIENT_KEY = CONFIG_FOLDER_PATH.joinpath("sql-client-key.pem")

# Get the SQL SSL certificate from Google Cloud Secret Manager API 
# and save/overwrite it to the local file system.
_SQL_SSL_DICT = {
    SQL_SERVER_CA: "sql-server-ca",
    SQL_CLIENT_CERT: "sql-client-cert",
    SQL_CLIENT_KEY: "sql-client-key"
}
for path in _SQL_SSL_DICT:
    with open(path, "w") as f:
        f.write(get_secret_payload(secretID=_SQL_SSL_DICT[path]))
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
    "host": REMOTE_SQL_SERVER_PASS, # Google Cloud SQL Public address
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