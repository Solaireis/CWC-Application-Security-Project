# import third party libraries
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants_Init import GOOGLE_TOKEN
else:
    from .Constants_Init import GOOGLE_TOKEN

# If modifying these scopes, delete the file token.json.
# Scopes details: https://developers.google.com/gmail/api/auth/scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

def google_init():
    """
    Initialise Google API by trying to authenticate with token.json
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    
    Returns:
    - Google API resource object
    """
    creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, SCOPES)

    # Build the Gmail service from the credentials
    gmailService = build("gmail", "v1", credentials=creds)

    return gmailService

if (__name__ == "__main__"):
    google_init()