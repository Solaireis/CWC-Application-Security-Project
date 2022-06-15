"""
This python file contains all the functions that does NOT requires the import of the
flask web application's app variable from __init__.py.

This is to prevent circular imports.
"""

# import python standard libraries
import uuid, pathlib
from datetime import datetime, timedelta
from typing import Union
from base64 import urlsafe_b64encode
from time import sleep
from hashlib import sha1

# import local python files
from .Errors import *
from .Google import SCOPES, TOKEN_PATH, PARENT_FOLDER_PATH

# import third party libraries
import requests as req

# For Gmail API (Third-party libraries)
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

def get_IP_address_blacklist(checkForUpdates:bool=True) -> tuple:
    """
    Get the IP address to blacklist from the server.
    Though this is not the most effective way of preventing malcious threat actors from
    accessing the server as they can use VPNs or spoof their ip address, 
    it acts as another layer of security.
    
    Args:
        - checkForUpdates:  If True, the function will check for updates to the blacklist.
                            Otherwise, it will just load from the saved text file if found.
    
    Returns:
        - A tuple containing the IP address to blacklist
    """
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    BLACKLIST_FILEPATH = PARENT_FOLDER_PATH.joinpath("databases", "blacklist.txt")

    if (checkForUpdates):
        response = req.get("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
        if (response.status_code != 200):
            print("Something went wrong!")
            return get_IP_address_blacklist(checkForUpdates=False)

        results = response.text.splitlines() 

        dateComment = results[3].split(",")[-1].split("+")[0].strip()
        lastUpdated = datetime.strptime(dateComment, "%d %b %Y %H:%M:%S")
        lastUpdated += timedelta(hours=6) # update the datetime to utc+8 from utc+2

        if (BLACKLIST_FILEPATH.exists()):
            with open(BLACKLIST_FILEPATH, "r") as f:
                txtFile = f.read()
            blacklist = txtFile.split("\n")
            date = datetime.strptime(blacklist[0], DATE_FORMAT)
            if (date >= lastUpdated):
                print("\nIP Address Blacklist is up to date!")
                print("Successfully loaded IP Address Blacklist from the saved file.\n")
                return tuple(blacklist[1:]) # return the blacklist if it is up to date

        blacklist = tuple([ip.split("\t")[0] for ip in results if (not ip.startswith("#"))])

        with open(BLACKLIST_FILEPATH, "w") as f:
            f.write(lastUpdated.strftime(DATE_FORMAT) + "\n")
            f.write("\n".join(blacklist))
        print("\nIP Address Blacklist, blacklist.txt, created/updated and loaded!\n")

        return blacklist
    else:
        if (BLACKLIST_FILEPATH.exists()):
            with open(BLACKLIST_FILEPATH, "r") as f:
                txtFile = f.read()
                blacklist = txtFile.split("\n")
            print("\nIP Address Blacklist loaded from the saved file.\n")
            return tuple(blacklist[1:])
        else:
            print("\nIP Address Blacklist not found!")
            print("IP Address Blacklist will not be loaded and will be empty!\n")
            return ()

def create_message(sender:str="coursefinity123@gmail.com", to:str="", subject:str="", messageText:str="") -> dict:
    """
    Create a message for an email.
    
    Args:
    - sender: Email address of the sender.
    - to: Email address of the receiver.
    - subject: The subject of the email message.
    - messageText: The text of the email message. (Can be HTML)

    Returns:
    A dictionary containing a base64url encoded email object.
    """
    message = MIMEText(messageText, "html")
    message["To"] = to
    message["From"] = sender
    message["Subject"] = subject
    return {"raw": urlsafe_b64encode(message.as_string().encode()).decode()}

def send_email(to:str="", subject:str="", messageText:str="") -> Union[dict, None]:
    """
    Create and send an email message.
    
    Args:
    - to: Email address of the receiver.
    - subject: The subject of the email message.
    - messageText: The text of the email message. (Can be HTML)
    
    Returns: 
    Message object, including message id or None if there was an error.
    """
    creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    sentMessage = None
    try:
        # Create an authorized Gmail API service instance.
        service = build("gmail", "v1", credentials=creds)

        # creates a message object and sets the sender, recipient, and subject.
        message = create_message(to=to, subject=subject, messageText=messageText)

        # send the message
        sentMessage = (service.users().messages().send(userId="me", body=message).execute())
        print(f"Email sent!")
    except HttpError as e:
        print("Failed to send email...")
        print(f"Error:\n{e}\n")

    return sentMessage

def pwd_has_been_pwned(password:str) -> bool:
    """
    Checks if the password is in the haveibeenpwned database.
    If it is found, it means that the password is weak and has been
    leaked in the dark web through breaches from other services/websites.
    
    Args:
        - password: The password to check
    
    Returns:
        - True if the password is in the database, False otherwise.
    """
    # hash the password (plaintext) using sha1 to check against the database
    passwordHash = sha1(password.encode("utf-8")).hexdigest().upper()

    # retrieve the list of possible range from the api database 
    # using the first five characters (to get the hash prefix) of the sha1 hash.
    results = []
    while (1):
        response = req.get(f"https://api.pwnedpasswords.com/range/{passwordHash[:5]}")
        if (response.status_code == 200):
            results = response.text.splitlines()
            break
        elif (response.status_code == 429):
            # haveibeenpwned API is rate limited, so wait for a while and try again
            print(f"Failed to retrieve data from pwnedpasswords.com. Retrying in 2 seconds...")
            sleep(2)
        else:
            print(f"Failed to retrieve data from pwnedpasswords.com.\nError code: {response.status_code}")
            raise HaveibeenpwnedRequestError("Failed to retrieve data from pwnedpasswords.com...")

    # compare the possible ranges with the hash suffix (after the first five characters) of the sha1 hash
    for result in results:
        if (result.split(":")[0] == passwordHash[5:]):
            # if the password has been found, return True
            return True
    return False

def generate_id() -> str:
    """
    Generates a unique ID
    """
    return uuid.uuid4().hex