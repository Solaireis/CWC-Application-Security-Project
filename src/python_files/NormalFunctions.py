"""
This python file contains all the functions that does NOT requires the import of the
flask web application's app variable from app.py.

This is to prevent circular imports.
"""

# import python standard libraries
from six import ensure_binary
import requests as req, uuid, re, json
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta
from typing import Union, Optional
from base64 import urlsafe_b64encode, urlsafe_b64decode
from time import time, sleep
from hashlib import sha1, sha384
from pathlib import Path

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants import CONSTANTS
    from Errors import *
else:
    from .Constants import CONSTANTS
    from .Errors import *

# import third party libraries
import PIL
from PIL import Image as PillowImage

# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google Gmail API (Third-party libraries)
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build, Resource

# For Google Cloud KMS (key management service) API (Third-party libraries)
from google_crc32c import Checksum as g_crc32c
from google.cloud import kms
from google.cloud.kms_v1.types import resources
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils

# For Google Cloud reCAPTCHA API (Third-party libraries)
from google.cloud import recaptchaenterprise_v1
from google.cloud.recaptchaenterprise_v1 import Assessment

"""------------------------------ Define Constants ------------------------------"""

# for comparing the date on the github repo
DATE_FORMAT = "%Y-%m-%d %H:%M:%S %z"
BLACKLIST_FILEPATH = CONSTANTS.ROOT_FOLDER_PATH.joinpath("databases", "blacklist.txt")

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
with open(CONSTANTS.ROOT_FOLDER_PATH.parent.absolute().joinpath("res", "filled_logo.png"), "rb") as f:
    LOGO_BYTES = f.read()

# For Google KMS asymmetric encryption and decryption
# TODO: Update the version if there is a rotation of the asymmetric keys
SESSION_COOKIE_ENCRYPTION_VERSION = 1
SIGNATURE_VERSION_ID = 1

# For 2FA setup key regex to validate if the setup is a valid base32 setup key
COMPILED_2FA_REGEX_DICT = {}
TWO_FA_CODE_REGEX = re.compile(r"^\d{6}$")

"""------------------------------ End of Defining Constants ------------------------------"""

def create_assessment(siteKey:str="", recaptchaToken:str="", recaptchaAction:Optional[str] = None) -> Assessment:
    """
    Creates an assessment in Google Cloud reCAPTCHA API.

    Args:
    - siteKey (str): The site key of the reCAPTCHA site.
    - recaptchaToken: The token that is sent to the Google Cloud reCAPTCHA API.
    - recaptchaAction: The action name that is expected to be performed by the user.

    Returns:
    - An Assessment object.
    """
    event = recaptchaenterprise_v1.Event()
    event.site_key = siteKey
    event.token = recaptchaToken
    if (recaptchaAction is not None):
        event.expected_action = recaptchaAction

    assessment = recaptchaenterprise_v1.Assessment()
    assessment.event = event

    projectName = f"projects/{CONSTANTS.GOOGLE_PROJECT_ID}"

    # construct the assessment request
    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.parent = projectName
    request.assessment = assessment

    # send to Google reCAPTCHA API
    response = CONSTANTS.RECAPTCHA_CLIENT.create_assessment(request)

    # check if the response is valid
    if (not response.token_properties.valid):
        print("invalid due to", response.token_properties.invalid_reason)
        raise InvalidRecaptchaTokenError("The reCAPTCHA token is not valid.")

    # check if the expected action was executed
    if (recaptchaAction is not None):
        if (response.token_properties.action != recaptchaAction):
            raise InvalidRecaptchaActionError("The reCAPTCHA action is not valid.")

    # get the risk score and the reason(s)
    # For more information on interpreting the assessment,
    # see: https://cloud.google.com/recaptcha-enterprise/docs/interpret-assessment
    # might wanna log this btw
    for reason in response.risk_analysis.reasons:
        print(reason)
    print("Risk score:", response.risk_analysis.score)
    return response

def score_within_acceptable_threshold(riskScore:int, threshold:float=0.5) -> bool:
    """
    Checks if the risk score is within the acceptable threshold.

    Args:
    - riskScore (int): The risk score of the reCAPTCHA token.
    - threshold (float): The acceptable threshold.
        - Range: 0.0 to 1.0
        - Defaults to 0.5 
        - https://cloud.google.com/recaptcha-enterprise/docs/best-practices-oat

    Returns:
    - True if the risk score is within the acceptable threshold.
    - False if the risk score is not within the acceptable threshold.
    """
    return (threshold <= riskScore)

def write_log_entry(logLocation:str="test-logs", logMessage:Union[dict, str]=None, severity:Optional[str]=None) -> None:
    """
    Writes an entry to the given log location.

    Args:
    - logLocation (str): The location of the log to write to
        - Defaults to "test-logs"
        - Will log to that location in the default log bucket
    - logMessage (str|dict): The message to write to the log
        - If str, the message is written to the log with the given severity
        - If dict, you can define your log message together with the severity in the dict.
            - Generally you will have a "message" key in the dict that contains the log entry
            and a "severity" key that contains the severity of the log entry.
        - More details on how to write the log messages:
            - https://cloud.google.com/logging/docs/samples/logging-write-log-entry
    - severity (str, optional): The severity of the log entry
        - If severity is defined in the dict type logMessage, you can leave the severity argument out
        - If the logMessage is a str, the severity argument is required
        - If severity is not defined, it will be set to "DEFAULT" severity
        - Available severity levels:
            - DEFAULT
            - DEBUG
            - INFO
            - NOTICE
            - WARNING
            - ERROR
            - CRITICAL
            - ALERT
            - EMERGENCY
        - More details on the severity type:
            - https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity
    """
    if (logMessage is None):
        raise ValueError("logMessage must be defined!")

    if (severity is None):
        severity = "DEFAULT"

    logger = CONSTANTS.LOGGING_CLIENT.logger(logLocation)

    if (isinstance(logMessage, dict)):
        logger.log_struct(logMessage)
    elif (isinstance(logMessage, str)):
        logger.log_text(logMessage, severity=severity)
    else:
        raise ValueError("logMessage must be a str or dict")

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
    keyName = CONSTANTS.KMS_CLIENT.crypto_key_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyName)

    # call Google Cloud KMS API to get the key's information
    response = CONSTANTS.KMS_CLIENT.get_crypto_key(request={"name": keyName})
    return response

def crc32c(data:Union[bytes, str]) -> int:
    """
    Calculates the CRC32C checksum of the provided data

    Args:
    - data (str|bytes): the bytes of the data which the checksum should be calculated
        - If the data is in string format, it will be encoded to bytes

    Returns:
    - An int representing the CRC32C checksum of the provided bytes
    """
    return int(g_crc32c(initial_value=ensure_binary(data)).hexdigest(), 16)

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
    keyVersionName = CONSTANTS.KMS_CLIENT.crypto_key_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyID)

    # construct and send the request to Google Cloud KMS API to encrypt the plaintext
    response = CONSTANTS.KMS_CLIENT.encrypt(request={"name": keyVersionName, "plaintext": plaintext, "plaintext_crc32c": plaintextCRC32C})

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
    keyVersionName = CONSTANTS.KMS_CLIENT.crypto_key_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyID)

    # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
    cipherTextCRC32C = crc32c(ciphertext)

    # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
    try:
        response = CONSTANTS.KMS_CLIENT.decrypt(request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C})
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
    keyName = CONSTANTS.KMS_CLIENT.crypto_key_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyName)

    # call the Google Cloud KMS API
    CONSTANTS.KMS_CLIENT.update_crypto_key_primary_version(request={"name": keyName, "crypto_key_version_id": versionID})

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
    keyName = CONSTANTS.KMS_CLIENT.crypto_key_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyName)

    # build the key version
    version = {}

    # call the Google Cloud KMS API
    response = CONSTANTS.KMS_CLIENT.create_crypto_key_version(request={"parent": keyName, "crypto_key_version": version})

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
    keyRingName = CONSTANTS.KMS_CLIENT.key_ring_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID)

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
        CONSTANTS.KMS_CLIENT.create_crypto_key(request={"parent": keyRingName, "crypto_key": key, "crypto_key_id": keyName})
    except (GoogleErrors.AlreadyExists):
        create_new_key_version(keyRingID=keyRingID, keyName=keyName, setNewKeyAsPrimary=True)

class JWTExpiryProperties:
    """
    Class to hold the JWT-like expiry properties feature.

    Note: Although it is implemented for the purpose of digitally signing a payload 
    and base64 encoding the payload with an active duration configured 
    and base64 encoding the signature, it is not a JWT as it has a major difference.

    Instead of being in the standard format:
    - "header.payload.signature"

    It is in the format of:
    - "payload.signature" as it is known that the web application will be 
    using a standardised EC algorithm to sign and verify the payload. 
    Hence, omitting the header data.

    In short:
    - It is used when digitally signing a payload and to configure an active duration time in seconds.
    """

    DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f %z"

    def __init__(self, activeDuration:Optional[int]=0, strDate:Optional[str]=None) -> None:
        """
        Initializes the JWTExpiryProperties object
        
        Args:
        - activeDuration (int, optional): the number of seconds the token is active.
        - strDate (str, optional): the date in the format of "YYYY-MM-DD HH:MM:SS".
        - Either one of the two parameters should be provided but NOT both.
        """
        if (strDate is None and activeDuration != 0):
            self.expiryDate = datetime.now().astimezone(tz=ZoneInfo("Asia/Singapore")) + timedelta(seconds=activeDuration)
        elif (strDate is not None and activeDuration == 0):
            self.expiryDate = datetime.strptime(strDate, DATE_FORMAT).astimezone(tz=ZoneInfo("Asia/Singapore"))
        elif (strDate is not None and activeDuration != 0):
            raise ValueError("Cannot specify both expirySeconds and strDate")
        else:
            raise ValueError("Either expirySeconds or strDate must be provided")

    def get_expiry_str_date(self) -> str:
        """
        Returns the expiry date in string type.
        
        E.g. "2022-06-26 17:21:20.123456 +0800"
        """
        return self.expiryDate.strftime(DATE_FORMAT)

    def is_expired(self) -> bool:
        """
        Returns True if the token has expired, False otherwise
        """
        return (datetime.now().astimezone(tz=ZoneInfo("Asia/Singapore")) > self.expiryDate)

    def __str__(self) -> str:
        return self.get_expiry_str_date()

    def __repr__(self) -> str:
        return self.get_expiry_str_date()

def EC_sign(
    payload:Union[str, dict]="", keyRingID:str="coursefinity", keyID:str="signing-key", 
    versionID:int=SIGNATURE_VERSION_ID, b64EncodeData:bool=False, expiry:JWTExpiryProperties=None
    ) -> Union[dict, bytes]:
    """
    Sign a message using the public key part of an asymmetric EC key.
    
    Args:
    - payload (str|dict|list): the payload to sign
        - Preferred type: str
            - You could use json.dumps(dict|list) before hand to convert the payload to a string.
        - Will convert the payload to a str by json.dumps() if payload is a dict or list.
            - Will raise a ValueError if the payload couldn't be converted to a string using json.dumps()
    - keyRingID: The ID of the key ring.
        - Defaults to "coursefinity
    - keyID: The ID of the key.
        - Defaults to "signing-key"
    - versionID: The version of the key.
        - Defaults to SIGNATURE_VERSION_ID defined in NormalFunctions.py
    - b64EncodeData: Whether to base64 encode the data or not.
        - Set this to True if you want to use the base64 encoded data for JWT.

    Returns:
    - A dictionary containing:
        - {\n
            "header": {
                "key_id" : key name used,
                "key_ring_id" : key ring name used,
                "version_id" : key version used
            },
            "data": {
                "payload" : the payload,
                "data_type" : the type of the data,
                "expiry" : the expiry date of the signature/token if defined
            },
            "signature": The signature of the data (bytes)
        }
    - If b64EncodeData is True, the return a base64 encoded bytes type.
        - header.payload.signature
    """
    # Construct the key version name
    keyVersionName = CONSTANTS.KMS_CLIENT.crypto_key_version_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyID, versionID)

    # Convert the payload to bytes
    if (isinstance(payload, dict)):
        dataType = "dict"
        try:
            payload = json.dumps(payload)
        except (TypeError):
            raise ValueError("Dict type payload is not JSON serializable")
    elif (isinstance(payload, list)):
        dataType = "list"
        try:
            payload = json.dumps(payload)
        except (TypeError):
            raise ValueError("Dict type payload is not JSON serializable")
    elif (isinstance(payload, str)):
        dataType = "str"
    else:
        raise ValueError("payload message must be either a dict or a str")
    encodedPayload = payload.encode("utf-8")

    # Compute the SHA384 hash of the encoded payload
    hash_ = sha384(encodedPayload).digest()

    # Compute the CRC32C checksum for data integrity checks
    digestCRC32C = crc32c(hash_)

    # Sign the digest by sending it to Google Cloud KMS API
    response = CONSTANTS.KMS_CLIENT.asymmetric_sign(
        request={"name": keyVersionName, "digest": {"sha384": hash_}, "digest_crc32c": digestCRC32C}
    )

    # Perform some integrity checks on the response that Google Cloud KMS API returned
    # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (not response.verified_digest_crc32c):
        # request sent to Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")
    if (response.name != keyVersionName):
        # request sent to Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")
    if (response.signature_crc32c != crc32c(response.signature)):
        # response received from Google Cloud KMS API was corrupted in-transit
        raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

    header = {"version_id": versionID, "key_ring_id": keyRingID, "key_id": keyID}
    data = {"payload": payload, "data_type": dataType}

    # If expiry is defined, set the expiry date in the data
    if (expiry is not None and isinstance(expiry, JWTExpiryProperties)):
        data["expiry"] = expiry.get_expiry_str_date()

    # Return the signature or the entire base64 encoded payload with the signature
    if (b64EncodeData):
        encodedDataList = [
            urlsafe_b64encode(json.dumps(header).encode("utf-8")),
            urlsafe_b64encode(json.dumps(data).encode("utf-8")),
            urlsafe_b64encode(response.signature)
        ]
        return b".".join(encodedDataList).decode("utf-8")
    else:
        return {"header":header, "data": data, "signature": response.signature}

def EC_verify(data:Union[dict, bytes, str]="", getData:bool=False) -> Union[dict, bool]:
    """
    Verify the signature of an message signed with an asymmetric EC key.
    
    Args:
    - data (dict|bytes|str): the data to verify
        - Note: If the data is instances of bytes or string, it will be treated as a base64 encoded data
    - getData: Whether to return the data or not.
        - Set this to True if the data is in base64 encoded format.
        - Generally True for JWT.

    Returns:
    - bool (true if verified and false otherwise)
    - dict (if getData is True)
        - {\n
            "header": {
                "key_id" : key name used,
                "key_ring_id" : key ring name used,
                "version_id" : key version used
            },
            "data": {
                "payload" : the payload,
                "data_type" : the type of the data,
                "expiry" : the expiry date of the signature/token if defined
            },
            "signature": The signature of the data (bytes)
            "verified": Whether the signature is valid or not (bool)
        }
    """
    # Get the data and the header, the signature, and the version ID
    if (isinstance(data, dict)):
        try:
            # get the data payload and its data type
            payloadData = data["data"]
            payload = payloadData["payload"]
            dataType = payloadData["data_type"]
            expiryDate = payloadData["expiry"] if ("expiry" in payloadData) else None

            # get the signature
            signature = data["signature"]

            # get the key info
            keyInfo = data["header"]
            keyID = keyInfo["key_id"]
            keyRingID = keyInfo["key_ring_id"]
            versionID = keyInfo["version_id"]
        except:
            # if some keys in the dict are missing, just return False by default
            return {"verified": False, "payload": data} if (getData) else False
    elif (isinstance(data, str) or isinstance(data, bytes)):
        # If data is base64 encoded, encode it to bytes
        if (isinstance(data, str)):
            data = data.encode("utf-8")

        # Base64 decode the data to get the payload and the signature
        newData = {}
        try:
            # Encoded base64 data is of the form:
            # header.data.signature
            b64EncodedDataList = data.split(b".")

            # get the data payload and its data type
            payloadInfo = json.loads(urlsafe_b64decode(b64EncodedDataList[1]).decode("utf-8"))
            payload = payloadInfo["payload"]
            dataType = payloadInfo["data_type"]
            expiryDate = payloadInfo["expiry"] if ("expiry" in payloadInfo) else None
            newData["data"] = payloadInfo

            # get the signature
            signature = urlsafe_b64decode(b64EncodedDataList[2])
            newData["signature"] = signature

            # get the key info
            keyInfo = json.loads(urlsafe_b64decode(b64EncodedDataList[0]).decode("utf-8"))
            keyID = keyInfo["key_id"]
            keyRingID = keyInfo["key_ring_id"]
            versionID = keyInfo["version_id"]
            newData["header"] = keyInfo
        except:
            # If base64 decoding fails or is missing some keys in the json payload, return False by default
            return {"verified": False, "data": data} if (getData) else False
        data = newData
    else:
        raise ValueError("data must be either a dict or bytes")

    # Construct the key version name
    keyVersionName = CONSTANTS.KMS_CLIENT.crypto_key_version_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyID, versionID)

    # Get the public key
    publicKey = CONSTANTS.KMS_CLIENT.get_public_key(request={"name": keyVersionName})

    # Extract and parse the public key as a PEM-encoded EC key
    publicKeyPEM = publicKey.pem.encode("utf-8")
    ecKey = serialization.load_pem_public_key(publicKeyPEM, default_backend())

    # Compute the SHA384 hash of the payload
    if (not isinstance(payload, bytes)):
        payload = payload.encode("utf-8")
    hash_ = sha384(payload).digest()

    # Attempt to verify the signature
    try:
        sha384_ = hashes.SHA384()
        ecKey.verify(signature, hash_, ec.ECDSA(utils.Prehashed(sha384_)))
        verified = True
    except (InvalidSignature):
        # If the signature is invalid or 
        # the payload has been tampered with, 
        # return false
        verified = False

    # Check if the token has an expiry key defined in the json
    if (verified and expiryDate is not None):
        # If so, check if the token has expired
        expiryObj = JWTExpiryProperties(strDate=expiryDate)
        verified = False if (expiryObj.is_expired()) else True

    # Return the data if requested
    if (getData):
        if (dataType == "dict" or dataType == "list"):
            try:
                data["data"]["payload"] = json.loads(data["data"]["payload"])
            except (TypeError):
                print("Warning: Could not parse JSON...")
        data["verified"] = verified
        return data
    else:
        return verified

def RSA_encrypt(plaintext:str="", keyRingID:str="coursefinity", keyID:str="encrypt-decrypt-key", versionID:int=SESSION_COOKIE_ENCRYPTION_VERSION) -> dict:
    """
    Encrypts the plaintext using Google KMS (RSA/asymmetric encryption)

    Args:
    - plaintext (str): The plaintext to encrypt
    - keyRingID (str): The ID of the key ring to use.
        - Defaults to "coursefinity"
    - keyID (str): The ID of the key to use for decryption.
        - Defaults to "encrypt-decrypt-key"
    - versionID (int): The version ID of the key to use for decryption.
        - Defaults to the defined SESSION_COOKIE_ENCRYPTION_VERSION variable

    Returns:
    - A dictionary containing the following keys:
        - {\n
            "header": {
                "key_ring_id" : key ring name used,
                "key_id" : key name used,
                "version_id" : key version used
            },
            "ciphertext": the encrypted plaintext in bytes
        }
    """
    # Build the key version name.
    keyVersionName = CONSTANTS.KMS_CLIENT.crypto_key_version_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyID, versionID)

    # get the public key
    publicKey = CONSTANTS.KMS_CLIENT.get_public_key(request={"name": keyVersionName})

    # Extract and parse the public key as a PEM-encoded RSA key
    pem = publicKey.pem.encode("utf-8")
    rsaKey = serialization.load_pem_public_key(pem, default_backend())

    # Construct the padding
    sha512 = hashes.SHA512()
    mgf = padding.MGF1(sha512)
    pad = padding.OAEP(mgf=mgf, algorithm=sha512, label=None)

    # Encrypt the data using the public key
    plaintext = plaintext.encode("utf-8")
    try:
        ciphertext = rsaKey.encrypt(plaintext, pad)
    except (ValueError) as e:
        print("Try reducing the length of the plaintext as RSA encryption can only encrypt small amounts of data.")
        raise EncryptionError(e)
    return {
            "header": {
                "key_ring_id": keyRingID,
                "key_id": keyID,
                "version_id": versionID
            },
            "ciphertext": ciphertext
        }

def RSA_decrypt(cipherData:dict=None) -> str:
    """
    Decrypts the ciphertext using Google KMS (RSA/asymmetric encryption)

    Args:
    - cipherData (dict): A dictionary containing the ciphertext and the version of the key used for encryption

    Returns:
    - The decrypted ciphertext (str)

    Raises:
    - RSACiphertextIsNotValidFormatError: If the ciphertext is not 
    - DecryptionError: If the decryption failed
    - CRC32ChecksumError: If the CRC32C checksum does not match
    """
    if (not isinstance(cipherData, dict)):
        raise RSACiphertextIsNotValidFormatError(
            f"The ciphertext, {cipherData} is in \"{type(cipherData)}\" format. Please pass in a dict type variable."
        )

    # retrieve the ciphertext and key information from the dict
    try:
        ciphertext = cipherData["ciphertext"]
        keyInfo = cipherData["header"]
        keyRingID = keyInfo["key_ring_id"]
        keyID = keyInfo["key_id"]
        versionID = keyInfo["version_id"]
    except (KeyError):
        raise RSACiphertextIsNotValidFormatError("The RSA ciphertext is missing some keys!")

    # Build the key version name.
    keyVersionName = CONSTANTS.KMS_CLIENT.crypto_key_version_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.LOCATION_ID, keyRingID, keyID, versionID)

    # encode it to bytes if the ciphertext is of string type
    if (isinstance(ciphertext, str)):
        ciphertext = ciphertext.encode("utf-8")

    # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
    cipherTextCRC32C = crc32c(ciphertext)

    # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
    try:
        response = CONSTANTS.KMS_CLIENT.asymmetric_decrypt(request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C})
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

        dateComment = results[3].split(",")[-1].strip()
        lastUpdated = datetime.strptime(dateComment, "%d %b %Y %H:%M:%S %z")
        # convert utc+2 to utc+8
        lastUpdated = lastUpdated.astimezone(tz=ZoneInfo("Asia/Singapore"))

        action = 0 # 1 for update, 0 for creating a new file
        if (BLACKLIST_FILEPATH.exists() and BLACKLIST_FILEPATH.is_file()):
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

        # Get the Google Gmail API authorised instance.
        GMAIL_CLIENT = get_gmail_client()

        # send the message
        sentMessage = (GMAIL_CLIENT.users().messages().send(userId="me", body=message).execute())
        print(f"Email sent!")
    except HttpError as e:
        print("Failed to send email...")
        print(f"Error:\n{e}\n")

    return sentMessage

def get_gmail_client() -> Resource:
    """
    Initialise Google API by trying to authenticate with token.json
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    
    Returns:
    - Google API resource object
    """
    # If modifying these scopes, delete the file token.json.
    # Scopes details: https://developers.google.com/gmail/api/auth/scopes
    SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

    # get the token.json file from Google Cloud Secret Manager API
    GOOGLE_TOKEN = json.loads(CONSTANTS.get_secret_payload(secretID="google-token"))

    creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, SCOPES)

    # Build the Gmail service from the credentials and return it
    return build("gmail", "v1", credentials=creds)

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
    # hash the password (plaintext) using sha1 to check 
    # against haveibeenpwned's database
    # but will not be stored in the MySQL database
    passwordHash = sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    hashPrefix = passwordHash[:5]
    hashSuffix = passwordHash[5:]
    del passwordHash

    # retrieve the list of possible range from the api database
    # using the first five characters (to get the hash prefix) of the sha1 hash.
    results = []
    while (1):
        response = req.get(f"https://api.pwnedpasswords.com/range/{hashPrefix}")
        if (response.status_code == 200):
            results = response.text.splitlines()
            break
        elif (response.status_code == 429):
            # haveibeenpwned API is rate limited, so wait for a while and try again
            print(f"Failed to retrieve data from api.pwnedpasswords.com. Retrying in 2 seconds...")
            sleep(2)
        else:
            print(f"Failed to retrieve data from api.pwnedpasswords.com.\nError code: {response.status_code}")
            # returns False (considered not leaked) 
            # but will rely on the checking of the password strength 
            # if user is signing up or changing password
            return False 

    # compare the possible ranges with the hash suffix (after the first five characters) of the sha1 hash
    for result in results:
        if (result.split(":")[0] == hashSuffix):
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
    Checks if the 2FA token is valid using the regex,
    ^[A-Z\d]{tokenLength}$

    Args:
    - token: The token to check.

    Returns:
    - True if the token is valid, False otherwise.
    """
    #
    length = len(token)
    if (length not in COMPILED_2FA_REGEX_DICT):
        # compile the regex if it has not been compiled yet
        COMPILED_2FA_REGEX_DICT[length] = re.compile(fr"^[A-Z2-7]{{{length}}}$")

    return True if (re.fullmatch(COMPILED_2FA_REGEX_DICT[length], token)) else False