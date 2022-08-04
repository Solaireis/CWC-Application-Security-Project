# import third party libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError
from google.api_core.exceptions import FailedPrecondition
from jsonschema import validate

# import python standard libraries
from sys import exit as sysExit
import pathlib, sys, json
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "python_files", "functions")

# add to sys path so that Constants.py can be imported by NormalFunctions.py
sys.path.append(str(PYTHON_FILES_PATH.parent))

# import NormalFunctions.py local python module using absolute path
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("NormalFunctions.py")
spec = spec_from_file_location("NormalFunctions", str(NORMAL_PY_FILE))
NormalFunctions = module_from_spec(spec)
sys.modules[spec.name] = NormalFunctions
spec.loader.exec_module(NormalFunctions)

CONSTANTS = NormalFunctions.CONSTANTS
SECRET_CONSTANTS = NormalFunctions.SECRET_CONSTANTS

# If modifying these scopes, delete the file token.json.
# Scopes details: https://developers.google.com/gmail/api/auth/scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

#TODO: Find the Google Token Schema
schema = {
    
}

def shutdown() -> None:
    """
    For UX, prints shutdown message.
    """
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")

def create_token() -> None:
    """
    Will try to initialise Google API by trying to authenticate with token.json
    stored in Google Cloud Platform Secret Manager API.

    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    """
    generatedNewToken = False
    creds = None

    GOOGLE_TOKEN = json.loads(
        SECRET_CONSTANTS.get_secret_payload(
            secretID=CONSTANTS.GOOGLE_TOKEN_NAME
        )
    )
    GOOGLE_CREDENTIALS = SECRET_CONSTANTS.GOOGLE_CREDENTIALS

    # Unsure if breaks
    # try:
    #     validate(instance=GOOGLE_TOKEN, schema=schema)
    # except Exception as e:
    #     print("Google Token Schema Validation Error:", e)
    #     sysExit(1)

    # The file google-token.json stores the user's access and refresh tokens,
    # and is stored in Google Secret Manager API.
    # It is created automatically when the authorization flow 
    # completes for the first time and will be saved to Google Secret Manager API.
    if (GOOGLE_TOKEN is not None):
        try:
            creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, SCOPES)
        except (RefreshError):
            print("Token is no longer valid as there is a refresh error!\n")
    else:
        print("No token found.\n")

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            print("Token is valid but might expire soon, refreshing token instead...", end="")
            creds.refresh(Request())
            print("\r\033[KRefreshed token!\n")
        else:
            print("Token is expired or invalid!\n")
            flow = InstalledAppFlow.from_client_config(GOOGLE_CREDENTIALS, SCOPES)
            creds = flow.run_local_server(port=0)

        print(f"Adding new secret version to the secret ID, {CONSTANTS.GOOGLE_TOKEN_NAME}...", end="")
        generatedNewToken = True

        # Save the credentials for the next run to Google Secret Manager API
        # construct the secret path to the secret key ID
        secretPath = SECRET_CONSTANTS.SM_CLIENT.secret_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.GOOGLE_TOKEN_NAME)

        # encode the credentials token to bytes
        secretData = creds.to_json().encode("utf-8")

        # calculate the credentials token payload crc32c checksum
        crc32cPayload = NormalFunctions.crc32c(secretData)

        # Now add the secret version and send to Google Secret Management API
        response = SECRET_CONSTANTS.SM_CLIENT.add_secret_version(parent=secretPath, payload={"data": secretData, "data_crc32c": crc32cPayload})
        print(f"\rNew secret version, {CONSTANTS.GOOGLE_TOKEN_NAME}, created:", response.name, "\n")

        while (1):
            destroyAllPastVer = input("Do you want to DESTROY all past versions? (Y/n): ").lower().strip()
            if (destroyAllPastVer not in ("y", "n", "")):
                print("Please enter a valid input!")
                continue
            else:
                destroyAllPastVer = True if (destroyAllPastVer != "n") else False
                break

        # disable all past versions if user wishes to do so
        if (destroyAllPastVer):
            print("Destroying all past versions...", end="")

            # get the latest secret version
            latestVer = int(response.name.split("/")[-1])

            for version in range(latestVer - 1, 0, -1):
                secretVersionPath = SECRET_CONSTANTS.SM_CLIENT.secret_version_path(
                    CONSTANTS.GOOGLE_PROJECT_ID, 
                    CONSTANTS.GOOGLE_TOKEN_NAME, 
                    version
                )
                try:
                    SECRET_CONSTANTS.SM_CLIENT.destroy_secret_version(request={"name": secretVersionPath})
                except (FailedPrecondition):
                    # key is already destroyed
                    break # assuming that all the previous has been destroyed
                    # otherwise, uncomment the code below
                    # pass
            print("\rDestroyed all past versions!", end="\n\n")

    try:
        # Build the Gmail service from the credentials
        with build("gmail", "v1", credentials=creds) as service:
            print(f"Status OK! {'Generated' if (generatedNewToken) else 'Loaded'} token.json is valid.")
    except (HttpError) as error:
        print(f"\nAn error has occurred:\n{error}")
        print()
        sysExit(1)

while (1):
    try:
        prompt = input("Do you want to save a new google-token.json? (y/N): ").lower().strip()
    except (KeyboardInterrupt):
        shutdown()
        sysExit(0)

    if (prompt not in ("y", "n", "")):
        print("Invalid input. Please try again.", end="\n\n")
        continue
    elif (prompt != "y"):
        print("\nShutting down...")
        input("Please press ENTER to exit...")
        sysExit(0)
    else:
        print(f"Will proceed to generate a new google-token.json. if it is invalid...", end="\n\n")
        break

create_token()