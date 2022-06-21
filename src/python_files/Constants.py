# import python standard libraries
import pathlib
from os import environ

# import third party libraries
from mysql.connector.constants import ClientFlag

"""------------------------ START OF DEFINING CONSTANTS ------------------------"""

# path to the root directory of the project
ROOT_FOLDER_PATH = pathlib.Path(__file__).parent.parent.absolute()

# for the config files folder
CONFIG_FOLDER_PATH = ROOT_FOLDER_PATH.joinpath("config_files")
CONFIG_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

# for Google Cloud API
GOOGLE_PROJECT_ID = "coursefinity-339412"

# for SQL SSL connection
SQL_SERVER_CA_PATH = CONFIG_FOLDER_PATH.joinpath("sql-server-ca.pem")
SQL_CLIENT_CERT_PATH = CONFIG_FOLDER_PATH.joinpath("sql-client-cert.pem")
SQL_CLIENT_KEY_PATH = CONFIG_FOLDER_PATH.joinpath("sql-client-key.pem")

# for SQL connection configuration
DATABASE_NAME = "coursefinity"
LOCAL_SQL_SERVER_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": environ["LOCAL_SQL_PASS"]
}
REMOTE_SQL_SERVER_CONFIG = {
    "host": environ["GOOGLE_CLOUD_MYSQL_SERVER"], # Google Cloud SQL Public address
    "user": "root",
    "password": environ["REMOTE_SQL_PASS"],
    "client_flags": [ClientFlag.SSL],
    "ssl_ca": str(SQL_SERVER_CA_PATH),
    "ssl_cert": str(SQL_CLIENT_CERT_PATH),
    "ssl_key": str(SQL_CLIENT_KEY_PATH)
}

# For Google GMAIL API
GOOGLE_CREDENTIALS_PATH = CONFIG_FOLDER_PATH.joinpath("google-credentials.json")
GOOGLE_TOKEN_PATH = CONFIG_FOLDER_PATH.joinpath("google-token.json")

# For Google Key Management Service API
GOOGLE_KMS_JSON_PATH = CONFIG_FOLDER_PATH.joinpath("google-kms.json")

# define the constants that can be imported elsewhere
__all__ = [
    ROOT_FOLDER_PATH,
    CONFIG_FOLDER_PATH,
    LOCAL_SQL_SERVER_CONFIG,
    REMOTE_SQL_SERVER_CONFIG,
    GOOGLE_CREDENTIALS_PATH,
    GOOGLE_TOKEN_PATH,
    GOOGLE_KMS_JSON_PATH
]

"""------------------------ END OF DEFINING CONSTANTS ------------------------"""

"""------------------------ START OF VERIFYING CONSTANTS ------------------------"""

# Do some checks that all the necessary file paths exists.
# Not that GOOGLE_TOKEN_PATH will not be checked 
# as it will be generated after running Google.py.
# Furthermore, it's already checked when running
# the main __init__.py file.
ALL_PATH_LIST = [
    SQL_SERVER_CA_PATH,
    SQL_CLIENT_CERT_PATH,
    SQL_CLIENT_KEY_PATH,
    GOOGLE_CREDENTIALS_PATH,
    GOOGLE_KMS_JSON_PATH
]
if (not all([path.exists() for path in ALL_PATH_LIST])):
    raise FileNotFoundError("Some files are missing. Please ensure that all the files are in the correct folder!")

"""------------------------ END OF VERIFYING CONSTANTS ------------------------"""