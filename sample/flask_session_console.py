# import python standard libraries
import pathlib, sys
from importlib.util import spec_from_file_location, module_from_spec

# import third-party libraries
from google.cloud.secretmanager import SecretVersion 
from google.api_core.exceptions import FailedPrecondition

def shutdown() -> None:
    """
    For UX, prints shutdown message.
    """
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "python_files", "functions")

# add to sys path so that Constants.py can be imported by NormalFunctions.py
sys.path.append(str(PYTHON_FILES_PATH.parent))

# import NormalFunctions.py local python module using absolute path
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("NormalFunctions.py")
spec = spec_from_file_location("NormalFunctions", str(NORMAL_PY_FILE))
NormalFunctions = module_from_spec(spec)
sys.modules[spec.name] = NormalFunctions
spec.loader.exec_module(NormalFunctions)

CONSTANTS = NormalFunctions.CONSTANTS
SECRET_CONSTANTS = NormalFunctions.SECRET_CONSTANTS

# Create an authorised Google Cloud Secret Manager API service instance.
SM_CLIENT = SECRET_CONSTANTS.SM_CLIENT

def upload_secret_to_gcp(secretName:str=None, secretValue:str="") -> SecretVersion:
    """
    Uploads a secret to Google Cloud Secret Manager.

    Args:
    - secretName (str): name of the secret to be uploaded
    - secretValue (str): value of the secret to be uploaded

    Returns:
    - SecretVersion: secret version object
    """
    # construct the secret path to the secret key ID
    secretPath = SM_CLIENT.secret_path(CONSTANTS.GOOGLE_PROJECT_ID, secretName)

    # calculate the payload crc32c checksum
    crc32cChecksum = NormalFunctions.crc32c(secretValue)

    # since it's in bytes, we don't need to encode the data payload to bytes
    # before sending it to Google Secret Management API.
    # Now add the secret version and send to Google Secret Management API
    response = SM_CLIENT.add_secret_version(
        parent=secretPath, payload={"data": secretValue, "data_crc32c": crc32cChecksum}
    )
    return response

MENU = """
-------------------------- Flask Secret Key Menu --------------------------

1. Generate a new secret key using GCP KMS API (Using RNG in a Cloud HSM)
2. View the secret key from GCP Secret Manager API
3. Generate a new 64 bytes salt (Using RNG in a Cloud HSM)
4. View the salt from GCP Secret Manager API
X. Shutdown test program

---------------------------------------------------------------------------"""
COMMAND = ("1", "2", "3", "4", "x")

def main() -> None:
    while (1):
        print(MENU)
        prompt = input("Enter command: ").lower().strip()
        if (prompt not in COMMAND):
            print("Please enter a valid input!")
            continue

        elif (prompt == "x"):
            shutdown()
            return

        elif (prompt == "1"):
            addKeyPrompt = "n"
            while (1):
                print("Generate and add a new Flask secret key to Google Secret Manager API?")
                addKeyPrompt = input("Enter command (y/N): ").lower().strip()
                if (addKeyPrompt not in ("y", "n", "")):
                    print("Please enter a valid input!")
                    continue
                else:
                    break

            print()
            if (addKeyPrompt != "y"):
                print("Generation of a new key will be aborted...")
                continue
            else:
                print("Generating a new Flask secret key...", end="")

            response = upload_secret_to_gcp(
                secretName=CONSTANTS.FLASK_SECRET_KEY_NAME, 
                secretValue=NormalFunctions.generate_secure_random_bytes(
                    nBytes=CONSTANTS.SESSION_NUM_OF_BYTES, generateFromHSM=True
                )
            )
            print(f"\rGenerated the new Flask secret key at \"{response.name}\"!", end="\n\n")

            while (1):
                destroyAllPastVer = input("Do you want to delete all past versions? (Y/n): ").lower().strip()
                if (destroyAllPastVer not in ("y", "n", "")):
                    print("Please enter a valid input!")
                    continue
                else:
                    destroyAllPastVer = True if (destroyAllPastVer != "n") else False
                    break

            # delete all past versions if user wishes to do so
            if (destroyAllPastVer):
                print("Destroying all past versions...", end="")

                # get the latest secret version
                latestVer = int(response.name.split("/")[-1])

                for version in range(latestVer - 1, 0, -1):
                    secretVersionPath = SM_CLIENT.secret_version_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.FLASK_SECRET_KEY_NAME, version)
                    try:
                        SM_CLIENT.destroy_secret_version(request={"name": secretVersionPath})
                    except (FailedPrecondition):
                        # key is already destroyed
                        break # assuming that all the previous has been destroyed
                        # otherwise, uncomment the code below
                        # pass
                print("\rDestroyed all past versions!", end="\n\n")

        elif (prompt == "2"):
            # construct the resource name of the secret version
            secretPayload = SECRET_CONSTANTS.get_secret_payload(secretID=CONSTANTS.FLASK_SECRET_KEY_NAME, decodeSecret=False)

            # print the secret payload (Not ideal but for demo)
            while (1):
                displayInHex = input("Do you want to view the secret key in hexadecimal format? (Y/n): ").lower().strip()
                if (displayInHex not in ("y", "n", "")):
                    print("Please enter a valid input!")
                    continue
                else:
                    displayInHex = True if (displayInHex != "n") else False
                    break

            if (displayInHex):
                secretPayload = secretPayload.hex()
            print(f"Generated secret key that is stored at Google Secret Manager API:\n{secretPayload}")
            del secretPayload

        elif (prompt == "3"):
            addKeyPrompt = "n"
            while (1):
                print("Generate and add a new salt for the Flask session cookie to Google Secret Manager API?")
                addKeyPrompt = input("Enter command (y/N): ").lower().strip()
                if (addKeyPrompt not in ("y", "n", "")):
                    print("Please enter a valid input!")
                    continue
                else:
                    break

            print()
            if (addKeyPrompt != "y"):
                print("Generation of a new salt will be aborted...")
                continue
            else:
                print("Generating a new salt for Flask session cookie...", end="")

            response = upload_secret_to_gcp(
                secretName=CONSTANTS.FLASK_SALT_KEY_NAME, 
                secretValue=NormalFunctions.generate_secure_random_bytes(
                    nBytes=CONSTANTS.SALT_NUM_OF_BYTES, generateFromHSM=True
                )
            )
            print(f"\rGenerated the new salt at \"{response.name}\"!", end="\n\n")

            while (1):
                destroyAllPastVer = input("Do you want to delete all past versions? (Y/n): ").lower().strip()
                if (destroyAllPastVer not in ("y", "n", "")):
                    print("Please enter a valid input!")
                    continue
                else:
                    destroyAllPastVer = True if (destroyAllPastVer != "n") else False
                    break

            # delete all past versions if user wishes to do so
            if (destroyAllPastVer):
                print("Destroying all past versions...", end="")

                # get the latest secret version
                latestVer = int(response.name.split("/")[-1])

                for version in range(latestVer - 1, 0, -1):
                    secretVersionPath = SM_CLIENT.secret_version_path(CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.FLASK_SALT_KEY_NAME, version)
                    try:
                        SM_CLIENT.destroy_secret_version(request={"name": secretVersionPath})
                    except (FailedPrecondition):
                        # key is already destroyed
                        break # assuming that all the previous has been destroyed
                        # otherwise, uncomment the code below
                        # pass
                print("\rDestroyed all past versions!", end="\n\n")

        elif (prompt == "4"):
            # construct the resource name of the secret version
            secretPayload = SECRET_CONSTANTS.get_secret_payload(secretID=CONSTANTS.FLASK_SALT_KEY_NAME, decodeSecret=False)

            # print the secret payload (Not ideal but for demo)
            while (1):
                displayInHex = input("Do you want to view the salt in hexadecimal format? (Y/n): ").lower().strip()
                if (displayInHex not in ("y", "n", "")):
                    print("Please enter a valid input!")
                    continue
                else:
                    displayInHex = True if (displayInHex != "n") else False
                    break

            if (displayInHex):
                secretPayload = secretPayload.hex()
            print(f"Generated salt that is stored at Google Secret Manager API:\n{secretPayload}")
            del secretPayload

try:
    main()
except (KeyboardInterrupt):
    shutdown()