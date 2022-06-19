"""
This python file contains all the functions that does NOT requires the import of the
flask web application's app variable from __init__.py.

This is to prevent circular imports.
"""

# import python standard libraries
import uuid, re, pathlib
from six import ensure_binary
from datetime import datetime, timedelta, timezone
from typing import Union
from base64 import urlsafe_b64encode
from time import sleep
from hashlib import sha1
from pathlib import Path
from json import dumps
from inspect import getframeinfo, stack
from os import environ

# import local python files
from .Errors import *
from .Google import PARENT_FOLDER_PATH, google_init

# import third party libraries
import requests as req
import PIL
from PIL import Image as PillowImage

# For Gmail API (Third-party libraries)
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from googleapiclient.errors import HttpError

# For Google KMS (key management service) API (Third-party libraries)
import crcmod
import google.api_core.exceptions as GoogleErrors
from google.cloud import kms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

"""------------------------------ Define Constants ------------------------------"""

# for comparing the date on the github repo
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
BLACKLIST_FILEPATH = PARENT_FOLDER_PATH.joinpath("databases", "blacklist.txt")

# Create an authorized Gmail API service instance.
GOOGLE_SERVICE = google_init(quiet=True)

# password regex follows OWASP's recommendations
# https://owasp.deteact.com/cheat/cheatsheets/Authentication_Cheat_Sheet.html#password-complexity
PASSWORD_REGEX = re.compile(r"""
^                                                                   # beginning of password
(?!.*([A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])\1{2})    # not more than 2 identical characters in a row
(?=.*?[a-z])                                                        # at least one lowercase letter
(?=.*?[A-Z])                                                        # at least one uppercase letter
(?=.*?[\d])                                                         # at least one digit
(?=.*?[!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])                  # at least one special character
[A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]                 # allowed characters
{10,}                                                               # at least 10 characters long  
$                                                                   # end of password
""", re.VERBOSE)

# for TOTP token
OTP_REGEX = re.compile(r"^[A-Z\d]{32}$")

# for email coursefinity logo image
with open(PARENT_FOLDER_PATH.parent.absolute().joinpath("res", "filled_logo.png"), "rb") as f:
    LOGO_BYTES = f.read()

# For Google KMS 
environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(PARENT_FOLDER_PATH.joinpath("kms_service_account.json"))
PROJECT_ID = "coursefinity-339412"
LOCATION_ID = "asia-southeast1"
KEY_RING_ID = "coursefinity"

"""------------------------------ End of Defining Constants ------------------------------"""

def crc32c(data):
    """
    Calculates the CRC32C checksum of the provided data
    
    Args:
    - data: the bytes over which the checksum should be calculated
    
    Returns:
    - An int representing the CRC32C checksum of the provided bytes
    """
    crc32cFunction = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32cFunction(ensure_binary(data))

def RSA_encrypt(plaintext:str="", keyID:str="encrypt-decrypt-key", versionID:int=1) -> bytes:
    """
    Encrypts the plaintext using Google KMS (RSA/asymmetric encryption)
    
    Args:
    - plaintext (str): The plaintext to encrypt
    - keyID (str): The ID of the key to use for decryption.
        - Defaults to "encrypt-decrypt-key"
    - versionID (int): The version ID of the key to use for decryption.
        - Defaults to 1
    
    Returns:
    - The encrypted plaintext (bytes)
    """

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key version name.
    keyVersionName = client.crypto_key_version_path(PROJECT_ID, LOCATION_ID, KEY_RING_ID, keyID, versionID)

    # get the public key
    publicKey = client.get_public_key(request={"name": keyVersionName})

    # Extract and parse the public key as a PEM-encoded RSA key
    pem = publicKey.pem.encode("utf-8")
    rsaKey = serialization.load_pem_public_key(pem, default_backend())

    # Construct the padding
    sha512 = hashes.SHA512()
    mgf = padding.MGF1(sha512)
    pad = padding.OAEP(mgf=mgf, algorithm=sha512, label=None)

    # Encrypt the data using the public key
    plaintext = plaintext.encode("utf-8")
    ciphertext = rsaKey.encrypt(plaintext, pad)
    return ciphertext

def RSA_decrypt(cipherText:bytes=b"", keyID:str="encrypt-decrypt-key", versionID:int=1) -> Union[str, None]:
    """
    Decrypts the ciphertext using Google KMS (RSA/asymmetric encryption)
    
    Args:
    - cipherText (bytes): The ciphertext to decrypt. 
    - keyID (str): The ID of the key to use for decryption.
        - Defaults to "encrypt-decrypt-key"
    - versionID (int): The version ID of the key to use for decryption.
        - Defaults to 1

    Returns:
    - The decrypted ciphertext (str)
    
    Raises:
    - CiphertextIsNotBytesError: If the ciphertext is not bytes
    """
    if (isinstance(cipherText, str)):
        raise CiphertextIsNotBytesError(f"The ciphertext, {cipherText}, is in string format. Please pass in bytes format.")

    if (not isinstance(cipherText, bytes)):
        raise CiphertextIsNotBytesError(f"The ciphertext, {cipherText} is not in bytes format. Please pass in bytes format.")

    # Create the client
    client = kms.KeyManagementServiceClient()

    # Build the key version name.
    keyVersionName = client.crypto_key_version_path(PROJECT_ID, LOCATION_ID, KEY_RING_ID, keyID, versionID)

    # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
    cipherTextCRC32C = crc32c(cipherText)

    # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
    try:
        response = client.asymmetric_decrypt(request={"name": keyVersionName, "ciphertext": cipherText, "ciphertext_crc32c": cipherTextCRC32C})
    except (GoogleErrors.InvalidArgument) as e:
        print("Error caught:")
        print(e)
        raise DecryptionError("Decryption failed or ciphertext is not 512 in length.")

    # Perform some integrity checks on the decrypted data that Google Cloud KMS API returned
    # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (not response.verified_ciphertext_crc32c):
        # request sent to Google Cloud KMS was corrupted in-transit
        raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")
    if (response.plaintext_crc32c != crc32c(response.plaintext)):
        # response received from Google Cloud KMS was corrupted in-transit
        raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

    return response.plaintext.decode("utf-8")

def compress_and_resize_image(imageData:bytes=None, imagePath:pathlib.Path=None, dimensions:tuple=None, quality:int=75, optimise:bool=True) -> str:
    """
    Resizes the image at the given path to the given dimensions and compresses it with the given quality.
    
    Converts the image to webp format as well for smaller image file size and saves the image to the given path.
    
    Args:
    - imageData (bytes): The image data to compress and resize
    - imagePath (pathlib.Path): The path to the image to resize
    - dimensions (tuple): The dimensions to resize the image to
        - Must be a tuple of two integers, e.g. (500, 500)
    - quality (int): The quality of the image to resize to
        - Must be an integer between 1 and 100
        - Defaults to 75
    - optimise (bool): Whether to optimise the image or not
        - Defaults to True
    
    Returns:
    - The path to the compressed image (pathlib.Path)
    
    Raises:
    - UnidentifiedImageError: If the image at the given path is not a valid image
    """
    try:
        # open image file
        image = PillowImage.open(imageData).convert("RGB")
    except (PIL.UnidentifiedImageError) as e:
        print("Error in resizing and compressing image...")
        print("Error message caught:")
        print(e)
        raise InvalidProfilePictureError("The image is not a valid image file.")

    # resize image if dimensions are defined
    if (dimensions is not None):
        resizedImage = image.resize(dimensions)
    else:
        resizedImage = image

    # changes the extension to .webp
    newImagePath = imagePath.with_suffix(".webp")

    # remove the image file if user has already uploaded one before
    newImagePath.unlink(missing_ok=True)

    # save the new and compressed image as webp
    resizedImage.save(newImagePath, format="webp", optimize=optimise, quality=quality)
    return newImagePath

def get_IP_address_blacklist(checkForUpdates:bool=True) -> list:
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
    if (checkForUpdates):
        response = req.get("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
        if (response.status_code != 200):
            print("Something went wrong!")
            return get_IP_address_blacklist(checkForUpdates=False)

        results = response.text.splitlines() 

        dateComment = results[3].split(",")[-1].split("+")[0].strip()
        lastUpdated = datetime.strptime(dateComment, "%d %b %Y %H:%M:%S")
        lastUpdated += timedelta(hours=6) # update the datetime to utc+8 from utc+2

        action = 0 # 1 for update, 0 for creating a new file
        if (BLACKLIST_FILEPATH.exists()):
            with open(BLACKLIST_FILEPATH, "r") as f:
                txtFile = f.read()
            blacklist = txtFile.split("\n")

            try:
                date = datetime.strptime(blacklist[0], DATE_FORMAT)
            except (ValueError):
                BLACKLIST_FILEPATH.unlink()
                return get_IP_address_blacklist()

            if (date >= lastUpdated):
                print("\nIP Address Blacklist is up to date!")
                print("Successfully loaded IP Address Blacklist from the saved file.\n")
                return blacklist[1:] # return the blacklist if it is up to date
            else:
                print("\nIP Address Blacklist is outdated!", end="")
                action = 1

        print("\nLoading IP Address Blacklist from the github repo...")
        blacklist = [ip.split("\t")[0] for ip in results if (not ip.startswith("#"))]

        with open(BLACKLIST_FILEPATH, "w") as f:
            f.write(lastUpdated.strftime(DATE_FORMAT) + "\n")
            f.write("\n".join(blacklist))
        print(f"IP Address Blacklist, blacklist.txt, {'created' if (action == 0) else 'updated'} and loaded!\n")

        return blacklist
    else:
        if (BLACKLIST_FILEPATH.exists()):
            with open(BLACKLIST_FILEPATH, "r") as f:
                txtFile = f.read()
            blacklist = txtFile.split("\n")

            # try to parse the date from the first line
            try:
                datetime.strptime(blacklist[0], DATE_FORMAT)
            except (ValueError):
                BLACKLIST_FILEPATH.unlink()
                return get_IP_address_blacklist(checkForUpdates=True) # true as a last resort

            print("\nLoading potentially outdated IP Address Blacklist from the saved text file...")
            print("Reason: GitHub repo link might be incorrect or GitHub is not available.\n")
            return blacklist[1:]
        else:
            print("\nIP Address Blacklist GitHub repo and text file were not found!")
            print("IP Address Blacklist will not be loaded and will be empty!")
            print("Reason: GitHub repo link might be incorrect or GitHub is not available.\n")
            return []

def create_message(sender:str="coursefinity123@gmail.com", to:str="", subject:str="", message:str="", name:str=None) -> dict:
    """
    Create a message for an email.
    
    Args:
    - sender: Email address of the sender.
    - to: Email address of the receiver.
    - subject: The subject of the email message.
    - message: The text of the email message. (Can be HTML)
    - name: The name of the recipient.

    Returns:
    A dictionary containing a base64url encoded email object.
    """
    htmlMessage = MIMEMultipart(_subtype="related")
    mainBody = f"""<p>Hello{f' {name}' if (name is not None) else ''},</p>

{message}

<p>
    Sincerely,<br>
    <strong>CourseFinity Support Team</strong>
</p>
<img src="cid:logo" alt="CourseFinity Logo" style="border-radius: 5px; width: min(250px, 40%);">
"""
    htmlMessage.attach(MIMEText(mainBody, _subtype="html"))

    # attach the logo image
    logoImage = MIMEImage(LOGO_BYTES, "png")
    logoImage.add_header("Content-ID", "<logo>")
    logoImage.add_header("Content-Disposition", "inline", filename="coursefinity_logo.png")
    htmlMessage.attach(logoImage)

    htmlMessage["To"] = to
    htmlMessage["From"] = sender
    htmlMessage["Subject"] = subject
    return {"raw": urlsafe_b64encode(htmlMessage.as_string().encode()).decode()}

def send_email(to:str="", subject:str="", body:str="") -> Union[dict, None]:
    """
    Create and send an email message.
    
    Args:
    - to: Email address of the receiver.
    - subject: The subject of the email message.
    - body: The text of the email message. (Can be HTML)
    
    Returns: 
    Message object, including message id or None if there was an error.
    """
    # creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    sentMessage = None
    try:
        # creates a message object and sets the sender, recipient, and subject.
        message = create_message(to=to, subject=subject, message=body)

        # send the message
        sentMessage = (GOOGLE_SERVICE.users().messages().send(userId="me", body=message).execute())
        print(f"Email sent!")
    except HttpError as e:
        print("Failed to send email...")
        print(f"Error:\n{e}\n")

    return sentMessage

def pwd_is_strong(password:str) -> bool:
    """
    Checks if the password is strong against the password regex.
    
    Args:
    - password: The password to check.
    
    Returns:
    - True if the password is strong, False otherwise.
    
    Password complexity requirements:
    - At least 10 characters long
    - At least one lowercase letter
    - At least one uppercase letter
    - At least one digit
    - At least one special character
    - Not more than two identical characters in a row
    
    Resources:
    - https://owasp.org/www-community/password-special-characters
    - https://owasp.deteact.com/cheat/cheatsheets/Authentication_Cheat_Sheet.html#password-complexity
    """
    return True if (re.fullmatch(PASSWORD_REGEX, password)) else False

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
            return False # returns False (considered not leaked) but will rely on the checking of the password strength

    # compare the possible ranges with the hash suffix (after the first five characters) of the sha1 hash
    for result in results:
        if (result.split(":")[0] == passwordHash[5:]):
            # if the password has been found, return True
            return True
    return False

def generate_id() -> str:
    """
    Generates a unique ID (32 bytes)
    """
    return uuid.uuid4().hex

def two_fa_token_is_valid(token:str) -> bool:
    """
    Checks if the 2FA token is valid.
    
    Args:
    - token: The token to check.
    
    Returns:
    - True if the token is valid, False otherwise.
    """
    return True if (re.fullmatch(OTP_REGEX, token)) else False

def log_event(levelname: str, message: str) -> None:
    """Logs an event to the log file.

    Parameters:
    - levelname   'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    - message     Additional notes for log.

    Returns: None
    """

    # Validation
    levelname = levelname.upper()
    if levelname not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        raise Exception("Level must be 'DEBUG', 'INFO', 'WARNING', 'ERROR' or 'CRITICAL'.")

    logPath = Path(__file__).parent.parent.joinpath('logs')

    # Get line number, module when this function was called, through stacking function frames
    lineNo = getframeinfo(stack()[1][0]).lineno
    module = Path(getframeinfo(stack()[1][0]).filename).stem

    # creates a folder for logs and dc if the folder alrd exists
    logPath.mkdir(parents=True, exist_ok=True)

    # Get date as log name
    time = datetime.now(timezone.utc).astimezone()
    readableDate = time.strftime('%Y-%m-%d')
    readableTime = time.strftime('%H:%M:%S')

    filename = logPath.joinpath(f'{readableDate}.log')


    # Log event to file    
    with open(filename, 'a') as log:
        # Based on logging module format
        log.write(f"{readableTime} [{levelname}] line {lineNo}, in {module}: {message}\n")

    # Log event to database
    data = dumps({'asctime' : readableTime,
                'levelname' : levelname,
                'module' : module,
                'message' : message})