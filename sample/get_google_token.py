# import third party libraries
from google.cloud import secretmanager
import google.api_core.exceptions as GoogleErrors
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

# import python standard libraries
from sys import exit as sysExit
import pathlib, json
FILE_PATH = pathlib.Path(__file__).parent.absolute()

def get_secret_payload(secretID:str="", versionID:str="latest") -> str:
    """
    Get the secret payload from Google Cloud Secret Manager API.
    
    Args:
    - secretID (str): The ID of the secret.
    - versionID (str): The version ID of the secret.
    
    Returns:
    - secretPayload (str): the secret payload
    """
    CONFIG_FOLDER_PATH = FILE_PATH.parent.joinpath("src", "config_files", "google-sm.json")
    if (not CONFIG_FOLDER_PATH.is_file()):
        print("\nError: Google Cloud Secret Manager configuration file not found!")
        print("Please create a configuration file in the config_files folder.")
        sysExit(1)

    SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(filename=CONFIG_FOLDER_PATH)
    
    # construct the resource name of the secret version
    secretName = SM_CLIENT.secret_version_path("coursefinity-339412", secretID, versionID)

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

def google_init(quiet:bool=False):
    """
    Initialise Google API by trying to authenticate with token.json
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    
    Args:
        - quiet: If True, will not print any messages.

    Returns:
        - Google API resource object if successful, None otherwise.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow 
    # completes for the first time.
    if (GOOGLE_TOKEN.is_file()):
        try:
            creds = Credentials.from_authorized_user_file(GOOGLE_TOKEN, SCOPES)
        except (RefreshError) as e:
            print("Error caught:")
            print(e)
            print("\nWill proceed to delete invalid token.json and create a new one...\n")
            GOOGLE_TOKEN.unlink(missing_ok=True)

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            creds.refresh(Request())
        else:
            if (GOOGLE_CREDENTIALS != "n"):
                flow = InstalledAppFlow.from_client_secrets_file(GOOGLE_CREDENTIALS, SCOPES)
            else:
                flow = InstalledAppFlow.from_client_config(GOOGLE_CREDENTIALS, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(GOOGLE_TOKEN, "w") as token:
            token.write(creds.to_json())
        print("Generated token.json successfully!")

    try:
        # Build the Gmail service from the credentials
        service = build("gmail", "v1", credentials=creds)

        if (not quiet):
            print("\nStatus OK! token.json is valid.")
        return service
    except HttpError as error:
        if (not quiet):
            print(f"\nAn error has occurred:\n{error}")
            print()

# If modifying these scopes, delete the file token.json.
# Scopes details: https://developers.google.com/gmail/api/auth/scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

while (1):
    loadLocally = input("Do you want to load credentials.json locally? (Y/n): ").lower().strip()
    if (loadLocally not in ("y", "n", "")):
        print("Invalid input. Please try again.", end="\n\n")
        continue
    else:
        print(f"Will proceed to load credentials.json {'locally' if (loadLocally != 'n') else 'from Google Secret Manager API'}...", end="\n\n")
        break

if (loadLocally != "n"):
    GOOGLE_CREDENTIALS = str(FILE_PATH.parent.joinpath("src", "config_files", "google-credentials.json"))
else:
    GOOGLE_CREDENTIALS = json.loads(get_secret_payload(secretID="google-credentials"))

GOOGLE_TOKEN = FILE_PATH.joinpath("google-token.json")
google_init()