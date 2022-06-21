# import third party libraries
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants_Init import GOOGLE_TOKEN, DEBUG_MODE
else:
    from .Constants_Init import GOOGLE_TOKEN, DEBUG_MODE

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
    if (DEBUG_MODE and GOOGLE_TOKEN.is_file()):
        try:
            creds = Credentials.from_authorized_user_file(GOOGLE_TOKEN, SCOPES)
        except (RefreshError) as e:
            print("Error caught:")
            print(e)
            print("\nWill proceed to delete invalid token.json...\n")
            GOOGLE_TOKEN.unlink(missing_ok=True)

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (DEBUG_MODE):
            raise Exception("Please generate a new token by running get_google_token.py in the sample folder!")
        elif (not DEBUG_MODE and GOOGLE_TOKEN is not None):
            creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, SCOPES)
        else:
            raise Exception("An unexpected error occurred while initialising Google Gmail API!")

    try:
        # Build the Gmail service from the credentials
        gmailService = build("gmail", "v1", credentials=creds)

        if (not quiet):
            print("\nStatus OK! token.json is valid.", end="\n\n")

        return gmailService
    except HttpError as error:
        if (not quiet):
            print(f"\nAn error has occurred:\n{error}")
            print()

if (__name__ == "__main__"):
    google_init()