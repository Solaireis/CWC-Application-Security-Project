# import third party libraries
from google.cloud import secretmanager
import google.api_core.exceptions as GoogleErrors
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError
from google_crc32c import Checksum as g_crc32c
from google.api_core.exceptions import FailedPrecondition

# import python standard libraries
from sys import exit as sysExit
import pathlib, json
from typing import Union
from six import ensure_binary

# Define constants
FILE_PATH = pathlib.Path(__file__).parent.absolute()
SM_FILE_PATH = FILE_PATH.parent.joinpath("src", "config_files", "google-sm.json")
GOOGLE_TOKEN_SECRET_NAME = "google-token"
PROJECT_ID = "coursefinity-339412"
SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(SM_FILE_PATH)

def shutdown() -> None:
    """
    For UX, prints shutdown message.
    """
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")

def crc32c(data:Union[bytes, str]) -> int:
    """
    Calculates the CRC32C checksum of the provided data
    
    Args:
    - data (str, bytes): the bytes of the data which the checksum should be calculated
        - If the data is in string format, it will be encoded to bytes
    
    Returns:
    - An int representing the CRC32C checksum of the provided bytes
    """
    return int(g_crc32c(initial_value=ensure_binary(data)).hexdigest(), 16)

def get_secret_payload(secretID:str="", versionID:str="latest") -> str:
    """
    Get the secret payload from Google Cloud Secret Manager API.
    
    Args:
    - secretID (str): The ID of the secret.
    - versionID (str): The version ID of the secret.
    
    Returns:
    - secretPayload (str): the secret payload
    """
    # construct the resource name of the secret version
    secretName = SM_CLIENT.secret_version_path(PROJECT_ID, secretID, versionID)

    # get the secret version
    try:
        response = SM_CLIENT.access_secret_version(request={"name": secretName})
    except (GoogleErrors.NotFound) as e:
        # secret version not found
        print("Error caught:")
        print(e, end="\n\n")
        return

    # return the secret payload
    return response.payload.data.decode("utf-8")

def create_token(quiet:bool=False) -> None:
    """
    Will try to initialise Google API by trying to authenticate with token.json
    stored inside the config_files folder (inside the src folder).
    
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    
    Args:
    - quiet: If True, will not print any messages.
    
    Returns:
    - None
    """
    generatedNewToken = False
    creds = None

    # The file google-token.json stores the user's access and refresh tokens,
    # and is stored in Google Secret Manager API.
    # It is created automatically when the authorization flow 
    # completes for the first time and will be saved to Google Secret Manager API.
    try:
        creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, SCOPES)
    except (RefreshError):
        print("Token is no longer valid as there is an refresh error!\n")

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_config(GOOGLE_CREDENTIALS, SCOPES)
            creds = flow.run_local_server(port=0)

        print(f"Adding new secret version to secret ID, {GOOGLE_TOKEN_SECRET_NAME}...", end="")
        generatedNewToken = True

        # Save the credentials for the next run to Google Secret Manager API
        # construct the secret path to the secret key ID
        secretPath = SM_CLIENT.secret_path(PROJECT_ID, GOOGLE_TOKEN_SECRET_NAME)

        # encode the credentials token to bytes
        secretData = creds.to_json().encode("utf-8")

        # calculate the credentials token payload crc32c checksum
        crc32cPayload = crc32c(secretData)

        # Now add the secret version and send to Google Secret Management API
        response = SM_CLIENT.add_secret_version(parent=secretPath, payload={"data": secretData, "data_crc32c": crc32cPayload})
        print(f"\rNew secret version, {GOOGLE_TOKEN_SECRET_NAME}, created:", response.name, "\n")

        while (1):
            disableAllPastVer = input("Do you want to disable all past versions? (Y/n): ").lower().strip()
            if (disableAllPastVer not in ("y", "n", "")):
                print("Please enter a valid input!")
                continue
            else:
                disableAllPastVer = True if (disableAllPastVer != "n") else False
                break

        # disable all past versions if user wishes to do so
        if (disableAllPastVer):
            print("Disabling all past versions...", end="")

            # get the latest secret version
            latestVer = int(response.name.split("/")[-1])

            for version in range(latestVer - 1, 0, -1):
                secretVersionPath = SM_CLIENT.secret_version_path(PROJECT_ID, GOOGLE_TOKEN_SECRET_NAME, version)
                try:
                    SM_CLIENT.destroy_secret_version(request={"name": secretVersionPath})
                except (FailedPrecondition):
                    # key is already destroyed
                    pass
            print("\rDisabled all past versions!", end="\n\n")

    try:
        # Build the Gmail service from the credentials
        service = build("gmail", "v1", credentials=creds)

        if (not quiet):
            print(f"Status OK! {'Generated' if (generatedNewToken) else 'Loaded'} token.json is valid.")

        service.close() # close the gmail api service object
    except HttpError as error:
        if (not quiet):
            print(f"\nAn error has occurred:\n{error}")
            print()
            sysExit(1)

# If modifying these scopes, delete the file token.json.
# Scopes details: https://developers.google.com/gmail/api/auth/scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

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

GOOGLE_CREDENTIALS = json.loads(get_secret_payload(secretID="google-credentials"))
GOOGLE_TOKEN = json.loads(get_secret_payload(secretID=GOOGLE_TOKEN_SECRET_NAME))
create_token()