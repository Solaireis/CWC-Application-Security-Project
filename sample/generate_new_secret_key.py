# import python standard libraries
from secrets import token_bytes
from sys import modules
import pathlib
from importlib.util import spec_from_file_location, module_from_spec

# Define constants
FILE_PATH = pathlib.Path(__file__).parent.absolute()
NUM_OF_BYTES = 512 # 512 bytes or 4096 bits

# import Constants_Init.py local python module using absolute path
CONSTANTS_INIT_PY_FILE = FILE_PATH.parent.joinpath("src", "python_files", "Constants_Init.py")
spec = spec_from_file_location("Constants_Init", str(CONSTANTS_INIT_PY_FILE))
Constants_Init = module_from_spec(spec)
modules[spec.name] = Constants_Init
spec.loader.exec_module(Constants_Init)

# Create an authorised Google Cloud Secret Manager API service instance.
SM_CLIENT = Constants_Init.SM_CLIENT

MENU = """
-------------------- Flask Secret Key Menu --------------------

1. Generate a new secret key
2. View the secret key from Google Cloud Secret Manager API
X. Shutdown test program

---------------------------------------------------------------"""
COMMAND = ("1", "2", "x")

def shutdown() -> None:
    """
    For UX, prints shutdown message.
    """
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")

def main() -> None:
    while (1):
        print(MENU)
        prompt = input("Enter command: ").lower().strip()
        if (prompt not in COMMAND):
            print("Please enter a valid input!")
            continue
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

            # generate a new key using the secrets module from Python standard library
            # as recommended by OWASP: 
            # https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation
            secretKey = token_bytes(NUM_OF_BYTES) 

            # construct the secret path to the secret key ID
            secretPath = SM_CLIENT.secret_path(Constants_Init.GOOGLE_PROJECT_ID, Constants_Init.FLASK_SECRET_KEY_NAME)

            # since it's in bytes, we don't need to encode the data payload to bytes
            # before sending it to Google Secret Management API.
            # Now add the secret version and send to Google Secret Management API
            response = SM_CLIENT.add_secret_version(parent=secretPath, payload={"data": secretKey})

            print(f"\rGenerated the new Flask secret key at \"{response.name}\"!", end="\n\n")
        elif (prompt == "2"):
            # construct the resource name of the secret version
            secretName = SM_CLIENT.secret_version_path(Constants_Init.GOOGLE_PROJECT_ID, Constants_Init.FLASK_SECRET_KEY_NAME, "latest")

            # get the secret version
            response = SM_CLIENT.access_secret_version(request={"name": secretName})

            # print the secret payload (Not ideal but for demo)
            print(f"Generated secret key that is stored at Google Secret Manager API:\n{response.payload.data}")
        elif (prompt == "x"):
            shutdown()
            return

try:
    main()
except (KeyboardInterrupt):
    shutdown()