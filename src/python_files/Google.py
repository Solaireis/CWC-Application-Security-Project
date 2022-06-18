import pathlib
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

PARENT_FOLDER_PATH = pathlib.Path(__file__).parent.parent.absolute()
TOKEN_PATH = PARENT_FOLDER_PATH.joinpath("token.json")
CREDENTIALS_PATH = PARENT_FOLDER_PATH.joinpath("credentials.json")

# If modifying these scopes, delete the file token.json.
# Scopes details: https://developers.google.com/gmail/api/auth/scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

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
    if (TOKEN_PATH.exists()):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(TOKEN_PATH, "w") as token:
            token.write(creds.to_json())

    try:
        # Build the Gmail service from the credentials
        service = build("gmail", "v1", credentials=creds)

        if (not quiet):
            print("\nStatus OK! token.json is valid.", end="\n\n")
        return service
    except HttpError as error:
        if (not quiet):
            print(f"\nAn error has occurred:\n{error}")
            print()

if (__name__ == "__main__"):
    google_init()