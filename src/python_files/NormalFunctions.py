"""
This python file contains all the functions that does NOT requires the import of the
flask web application's app variable from __init__.py.

This is to prevent circular imports.
"""

# import python standard libraries
from six import ensure_binary
import uuid, re
import requests as req
from datetime import datetime, timedelta, timezone
from typing import Union
from base64 import urlsafe_b64encode
from time import time, sleep
from hashlib import sha1
from pathlib import Path
from json import loads, dumps
from inspect import getframeinfo, stack
from os import environ

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants_Init import ROOT_FOLDER_PATH, KMS_CLIENT, GOOGLE_PROJECT_ID, LOCATION_ID, GOOGLE_SERVICE
    from Errors import *
else:
    from .Constants_Init import ROOT_FOLDER_PATH, KMS_CLIENT, GOOGLE_PROJECT_ID, LOCATION_ID, GOOGLE_SERVICE
    from .Errors import *

# import third party libraries
import PIL
from PIL import Image as PillowImage

# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Gmail API (Third-party libraries)
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from googleapiclient.errors import HttpError

# For Google KMS (key management service) API (Third-party libraries)
import crcmod
from google.cloud import kms
from google.cloud.kms_v1.types import resources
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

"""------------------------------ Define Constants ------------------------------"""

# for comparing the date on the github repo
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
BLACKLIST_FILEPATH = ROOT_FOLDER_PATH.joinpath("databases", "blacklist.txt")

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

# for email coursefinity logo image
with open(ROOT_FOLDER_PATH.parent.absolute().joinpath("res", "filled_logo.png"), "rb") as f:
    LOGO_BYTES = f.read()

# For Google KMS asymmetric encryption and decryption
SESSION_COOKIE_ENCRYPTION_VERSION = 1 # update the version if there is a rotation of the asymmetric keys

"""------------------------------ End of Defining Constants ------------------------------"""

def get_key_info(keyRingID:str="", keyName:str="") -> resources.CryptoKey:
    """
    Get information about a key in Google Cloud KMS API.
    
    Args:
    - keyRingID (str): The ID of the key ring.
    - keyName (str): the name of the key to get information about
    
    Returns:
    - keyInfo (google.cloud.kms_v1.types.resources.CryptoKey): the key information
    """
    # Construct the key name
    keyName = KMS_CLIENT.crypto_key_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyName)

    # call Google Cloud KMS API to get the key's information
    response = KMS_CLIENT.get_crypto_key(request={"name": keyName})
    return response

def crc32c(data) -> int:
    """
    Calculates the CRC32C checksum of the provided data
    
    Args:
    - data: the bytes over which the checksum should be calculated
    
    Returns:
    - An int representing the CRC32C checksum of the provided bytes
    """
    crc32cFunction = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32cFunction(ensure_binary(data))

def symmetric_encrypt(plaintext:str="", keyRingID:str="coursefinity-users", keyID:str="") -> bytes:
    """
    Using Google Symmetric Encryption Algorithm, encrypt the provided plaintext.
    
    Args:
    - plaintext (str): the plaintext to encrypt
    - keyRingID (str): the key ring ID
        - Defaults to "coursefinity-users"
    - keyID (str): the key ID/name of the key
    
    Returns:
    - ciphertext (bytes): the ciphertext
    """
    plaintext = plaintext.encode("utf-8")

    # compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
    plaintextCRC32C = crc32c(plaintext)

    # Construct the key version name
    keyVersionName = KMS_CLIENT.crypto_key_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyID)

    # construct and send the request to Google Cloud KMS API to encrypt the plaintext
    response = KMS_CLIENT.encrypt(request={"name": keyVersionName, "plaintext": plaintext, "plaintext_crc32c": plaintextCRC32C})

    # Perform some integrity checks on the encrypted data that Google Cloud KMS API returned
    # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (not response.verified_plaintext_crc32c):
        # request sent to Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")
    if (response.ciphertext_crc32c != crc32c(response.ciphertext)):
        # response received from Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")

    return response.ciphertext

def symmetric_decrypt(ciphertext:bytes=b"", keyRingID:str="coursefinity-users", keyID:str="") -> str:
    """
    Using Google Symmetric Encryption Algorithm, decrypt the provided ciphertext.
    
    Args:
    - ciphertext (bytes): the ciphertext to decrypt
    - keyRingID (str): the key ring ID
        - Defaults to "coursefinity-users"
    - keyID (str): the key ID/name of the key
    
    Returns:
    - plaintext (str): the plaintext
    
    Raises:
    - CiphertextIsNotBytesError: If the ciphertext is not bytes
    - DecryptionError: If the decryption failed
    - CRC32ChecksumError: If the CRC32C checksum does not match
    """
    if (isinstance(ciphertext, bytearray)):
        ciphertext = bytes(ciphertext)
    
    if (not isinstance(ciphertext, bytes)):
        raise CiphertextIsNotBytesError(f"The ciphertext, {ciphertext} is in \"{type(ciphertext)}\" format. Please pass in a bytes type variable.")

    # Construct the key version name
    keyVersionName = KMS_CLIENT.crypto_key_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyID)

    # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
    cipherTextCRC32C = crc32c(ciphertext)

    # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
    try:
        response = KMS_CLIENT.decrypt(request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C})
    except (GoogleErrors.InvalidArgument) as e:
        print("Error caught while decrypting (symmetric):")
        print(e)
        raise DecryptionError("Symmetric Decryption failed.")

    # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
    # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (response.plaintext_crc32c != crc32c(response.plaintext)):
        # response received from Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

    return response.plaintext.decode("utf-8")

def update_key_set_primary(keyRingID:str="coursefinity-users", keyName:str="", versionID:str=None) -> None:
    """
    Set a new key version as the primary key version for encryption and decryption.
    
    Args:
    - keyRingID (str): the key ring ID
    - keyName (str): the name of the key to create (acts as the key ID)
    - versionID (str): the key version to set the primary key version for the specificed keyName (e.g. "1")
    
    Returns:
    - None
    """
    # Construct the parent key name
    keyName = KMS_CLIENT.crypto_key_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyName)

    # call the Google Cloud KMS API
    KMS_CLIENT.update_crypto_key_primary_version(request={"name": keyName, "crypto_key_version_id": versionID})

def create_new_key_version(keyRingID:str="coursefinity-users", keyName:str="", setNewKeyAsPrimary:bool=False) -> None:
    """
    In the event that the key ID already exists
    
    because Google Cloud KMS API does not allow deletion of keys but only the key versions and materials,
    
    hence, use this function to create a new key version for that existing key ID.
    
    Args:
    - keyRingID (str): the key ring ID
    - keyName (str): the name of the key to create (acts as the key ID)
    - setNewKeyAsPrimary (bool): Whether to set the new key version as the primary key
        - If true, the new key version will be set as the primary key version for encryption and decryption
        - Must be careful as old data encrypted with the old key version may not be able to be decrypted after 30 to 3 hours.
        - More details: https://cloud.google.com/kms/docs/consistency#key_versions
    
    Returns:
    - None
    """
    # Construct the parent key name
    keyName = KMS_CLIENT.crypto_key_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyName)

    # build the key version
    version = {}

    # call the Google Cloud KMS API
    response = KMS_CLIENT.create_crypto_key_version(request={"parent": keyName, "crypto_key_version": version})

    if (setNewKeyAsPrimary):
        # get the latest version from the response
        latestVersion = response.name.rsplit("/", 1)[-1]

        # set the latest version as the primary key version
        update_key_set_primary(keyRingID=keyRingID, keyName=keyName, versionID=latestVersion)

def create_symmetric_key(keyRingID:str="coursefinity-users", keyName:str="") -> None:
    """
    Create a new symmetric key.

    Args:
    - keyRingID (str): the key ring ID
    - keyName (str): the name of the key to create (acts as the key ID)
    
    Returns:
    - None
    """
    # Construct the parent key ring name
    keyRingName = KMS_CLIENT.key_ring_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID)

    # construct the key
    purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION

    # configure key settings
    key = {
        "purpose": purpose,
        "version_template": {
            "algorithm": algorithm,
            "protection_level": kms.ProtectionLevel.HSM
        },
        "rotation_period": {
            "seconds": 60 * 60 * 24 * 30, # 30 days
        },  
        "next_rotation_time": {
            "seconds": int(time()) + 60 * 60 * 24, # 24 hours from now
        }
    }

    # call Google Cloud KMS API to create the key
    try:
        KMS_CLIENT.create_crypto_key(request={"parent": keyRingName, "crypto_key": key, "crypto_key_id": keyName})
    except (GoogleErrors.AlreadyExists):
        create_new_key_version(keyRingID=keyRingID, keyName=keyName, setNewKeyAsPrimary=True)

def RSA_encrypt(plaintext:str="", keyID:str="encrypt-decrypt-key", keyRingID:str="coursefinity", versionID:int=SESSION_COOKIE_ENCRYPTION_VERSION) -> dict:
    """
    Encrypts the plaintext using Google KMS (RSA/asymmetric encryption)
    
    Args:
    - plaintext (str): The plaintext to encrypt
    - keyID (str): The ID of the key to use for decryption.
        - Defaults to "encrypt-decrypt-key"
    - keyRingID (str): The ID of the key ring to use.
        - Defaults to "coursefinity"
    - versionID (int): The version ID of the key to use for decryption.
        - Defaults to the defined SESSION_COOKIE_ENCRYPTION_VERSION variable
    
    Returns:
    - A dictionary containing the following keys:
        - ciphertext (bytes): The ciphertext
        - version (int): The version of the key used for encryption
    """
    # Build the key version name.
    keyVersionName = KMS_CLIENT.crypto_key_version_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyID, versionID)

    # get the public key
    publicKey = KMS_CLIENT.get_public_key(request={"name": keyVersionName})

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
    return {"ciphertext": ciphertext, "version": versionID}

def RSA_decrypt(cipherData:dict=None, keyID:str="encrypt-decrypt-key", keyRingID:str="coursefinity") -> str:
    """
    Decrypts the ciphertext using Google KMS (RSA/asymmetric encryption)
    
    Args:
    - cipherData (dict): A dictionary containing the ciphertext and the version of the key used for encryption
    - keyID (str): The ID of the key to use for decryption.
        - Defaults to "encrypt-decrypt-key"
    - keyRingID (str): The ID of the key ring to use.
        - Defaults to "coursefinity"
    
    Returns:
    - The decrypted ciphertext (str)
    
    Raises:
    - CiphertextIsNotBytesError: If the ciphertext is not bytes
    - DecryptionError: If the decryption failed
    - CRC32ChecksumError: If the CRC32C checksum does not match
    """
    if (not isinstance(cipherData, dict)):
        raise CiphertextIsNotBytesError(f"The cipher data, {cipherData} is in \"{type(cipherData)}\" format. Please pass in a dictionary type variable.")

    # Build the key version name.
    keyVersionName = KMS_CLIENT.crypto_key_version_path(GOOGLE_PROJECT_ID, LOCATION_ID, keyRingID, keyID, cipherData["version"])

    # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
    ciphertext = cipherData["ciphertext"]
    cipherTextCRC32C = crc32c(ciphertext)

    # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
    try:
        response = KMS_CLIENT.asymmetric_decrypt(request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C})
    except (GoogleErrors.InvalidArgument) as e:
        print("Error caught:")
        print(e)
        raise DecryptionError("Decryption failed or ciphertext is not 512 in length.")

    # Perform some integrity checks on the decrypted data that Google Cloud KMS API returned
    # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (not response.verified_ciphertext_crc32c):
        # request sent to Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")
    if (response.plaintext_crc32c != crc32c(response.plaintext)):
        # response received from Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

    return response.plaintext.decode("utf-8")

def compress_and_resize_image(imageData:bytes=None, imagePath:Path=None, dimensions:tuple=None, quality:int=75, optimise:bool=True) -> str:
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
    htmlMessage["Subject"] = " ".join(["[CourseFinity]", subject])
    return {"raw": urlsafe_b64encode(htmlMessage.as_string().encode()).decode()}

def send_email(to:str="", subject:str="", body:str="", name:str=None) -> Union[dict, None]:
    """
    Create and send an email message.
    
    Args:
    - to: Email address of the receiver.
    - subject: The subject of the email message.
    - body: The text of the email message. (Can be HTML)
    - name: The name of the recipient.
    
    Returns: 
    Message object, including message id or None if there was an error.
    """
    sentMessage = None
    try:
        # creates a message object and sets the sender, recipient, and subject.
        message = create_message(to=to, subject=subject, message=body, name=name)

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

def two_fa_token_is_valid(token:str, length=32) -> bool:
    """
    Checks if the 2FA token is valid.
    
    Args:
    - token: The token to check.
    
    Returns:
    - True if the token is valid, False otherwise.
    """
    # regex, ^[A-Z\d]{length}$
    return True if (re.fullmatch("".join([r"^[A-Z\d]{", f"{length}", r"}$"]), token)) else False

def get_splunk_token(eventCollectorName: str = 'Logging') -> str:
    """
    Retrieves the Splunk token from Splunk server. 
    Since the token is different for every implementation, it cannot be hardcoded.
    
    Returns:
    - The Splunk token.
    """

    response = req.get(url = 'https://localhost:8089/services/data/inputs/http',
                       auth = ('coursefinity', environ.get("EMAIL_PASS")), 
                       params = {'output_mode': 'json'}, 
                       verify = False
                      )
    
    # print(response.content)
    response = loads(response.content)['entry']

    for respond in response:
        if re.sub('http://|https://', "", respond['name']) == eventCollectorName:
            token = respond['content']['token']

    return token

def log_event(levelname: str, details: str, userID: str, IP: str, eventCollectorIndex: str = 'main') -> None:
    """Logs an event to the log file.

    Parameters:
    - levelname   'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    - details     Additional notes for log.

    Returns:
    - None
    """

    # Input Validation
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
    utcTime = datetime.now(timezone.utc).astimezone()
    readableDate = utcTime.strftime('%Y-%m-%d')
    readableTime = utcTime.strftime('%H:%M:%S')

    filename = logPath.joinpath(f'{readableDate}.log')

    # Log event to file    
    with open(filename, 'a') as log:
        # Based on logging module format
        log.write(f"{readableTime} [{levelname}] line {lineNo}, in {module}: {details}\n")
        # userID?
        # IP?

    # Log event to Splunk

    data = dumps({'index' : eventCollectorIndex,
                  'source' : module,
                  'time'  : time(),
                  'event' : {'levelName' : levelname,
                             'userID'  : userID,
                             'IP'      : IP,
                             'line'    : lineNo,
                             'details' : details
                            }
                })

    splunk_log(data)

def splunk_log_integrity_check(ackID):

    eventCollectorName = 'CourseFinity Logging'

    # Get event collector token (differs per implementation)
    response = req.get(url = 'https://localhost:8089/services/data/inputs/http', 
                   auth = ('coursefinity', environ.get("EMAIL_PASS")), 
                   params = {'output_mode': 'json'}, 
                   verify = False
                  )
    # print(response.content)

    response = loads(response.content)['entry']

    for respond in response:
        if re.sub('http://|https://', "", respond['name']) == eventCollectorName:
            token = respond['content']['token']

    response = req.post(url = 'http://127.0.0.1:8088/services/collector/ack',

                        params = {
                                  'channel': '8cfb8d79-4d19-4841-a868-18867be0eae6' # Same UUID as in LogExample.py, NormalFunction.py
                                 },

                        headers = {
                                   'Authorization': f'Splunk {token}',
                                   'Content-Type': 'application/x-www-form-urlencoded',
                                  },

                        data = dumps({
                                      'acks' : [ackID]
                                    })
                       )
    return loads(response.content)["acks"][str(ackID)]

def splunk_log(data: str, attempts: int = 5) -> bool:
    # Log event to database: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    
    response = req.post(url = 'http://127.0.0.1:8088/services/collector/event',

                        headers = {
                                   'Authorization': f"Splunk {get_splunk_token()}",
                                   "X-Splunk-Request-Channel": '8cfb8d79-4d19-4841-a868-18867be0eae6', # Static UUID value
                                   "Content-Type": "application/json",
                                  },

                        data = data
                       )
    # print(data)
    print(response.content)
    ackID = loads(response.content)['ackId']
    
    # Check if the event was logged successfully
    while not splunk_log_integrity_check(ackID):
        attempts -= 1
        if attempts == 0:
            splunk_fail_log()
            temp_splunk_backup(data)
            
            break

def temp_splunk_backup(data):
    # creates a folder for logs and dc if the folder alrd exists
    bakPath = Path(__file__).parent.parent.joinpath('logs')
    bakPath.mkdir(parents=True, exist_ok=True)

    filename = bakPath.joinpath('splunk_backup.bak')
    # print(data)
    
    with open(filename, 'a') as backup:
        backup.write(f"{data}\n")

def splunk_fail_log():
    logPath = Path(__file__).parent.parent.joinpath('logs')

    # Get line number, module when this function was called, through stacking function frames
    lineNo = getframeinfo(stack()[3][0]).lineno
    module = Path(getframeinfo(stack()[3][0]).filename).stem

    # creates a folder for logs and dc if the folder alrd exists
    logPath.mkdir(parents=True, exist_ok=True)

    # Get date as log name
    utcTime = datetime.now(timezone.utc).astimezone()
    readableDate = utcTime.strftime('%Y-%m-%d')
    readableTime = utcTime.strftime('%H:%M:%S')

    filename = logPath.joinpath('splunk_failure.log')

    levelname = 'WARNING'

    # Log event to file    
    with open(filename, 'a') as log:
        # Based on logging module format
        log.write(f"{readableDate} {readableTime} [{levelname}] line {lineNo}, in {module}: Splunk Server Logging Failure\n")

def splunk_log_retry():

    # creates a folder for logs and dc if the folder alrd exists
    logPath = Path(__file__).parent.parent.joinpath('logs')
    logPath.mkdir(parents=True, exist_ok=True)

    fileName = logPath.joinpath('splunk_backup.bak')
    with open(fileName, 'r+') as backup:
        lines = backup.readlines()

        if lines == []: # No need to query if nothing to query
            return

        data = "".join((line[:-1] for line in lines)) # Tuple faster
        
        response = req.post(url = 'http://127.0.0.1:8088/services/collector', 
                            headers = {
                                       'Authorization': f'Splunk {get_splunk_token()}',
                                      }, 
                            params = {
                                      'channel': '8cfb8d79-4d19-4841-a868-18867be0eae6' # Same UUID as in LogExample.py, NormalFunction.py
                                     },
                            data = data
                           )

        print(response.content)
        ackID = loads(response.content)['ackId']

        if splunk_log_integrity_check(ackID):
            backup.truncate(0)  # Delete all temporary lines
        