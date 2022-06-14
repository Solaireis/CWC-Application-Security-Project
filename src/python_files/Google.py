import pathlib
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

TOKEN_PATH = pathlib.Path(__file__).parent.parent.resolve().joinpath("token.json")

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.send"]

def google_init():
    """
    Initialise Google API by trying to authenticate with token.json
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow 
    # completes for the first time.
    if (TOKEN_PATH.exists()):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        # Try calling Gmail API
        service = build("gmail", "v1", credentials=creds)
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])

        if (labels is None):
            print("Something went wrong!")
            return
        print("Status OK! Authenticated with Google Gmail API.")
    except HttpError as error:
        print(f"An error has occurred:\n{error}")
        print()
        print("Please contact KJHJason (on discord) for help.")

if (__name__ == "__main__"):
    google_init()