# import third party libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants import GOOGLE_TOKEN_PATH, GOOGLE_CREDENTIALS_PATH
else:
    from .Constants import GOOGLE_TOKEN_PATH, GOOGLE_CREDENTIALS_PATH

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
    if (GOOGLE_TOKEN_PATH.is_file()):
        try:
            creds = Credentials.from_authorized_user_file(GOOGLE_TOKEN_PATH, SCOPES)
        except (RefreshError) as e:
            print("Error caught:")
            print(e)
            print("\nWill proceed to delete invalid token.json and create a new one...\n")
            GOOGLE_TOKEN_PATH.unlink(missing_ok=True)

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GOOGLE_CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(GOOGLE_TOKEN_PATH, "w") as token:
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