# import third party libraries
import pymysql

# import python standard libraries
from sys import exit as sysExit
import re, pathlib, sys
from datetime import datetime
from zoneinfo import ZoneInfo
from importlib.util import spec_from_file_location, module_from_spec

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

"""----------------------------------- START OF DEFINING FUNCTIONS -----------------------------------"""

def shutdown() -> None:
    """For UX, prints shutdown message."""
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")
    sysExit(0)

def print_menu() -> None:
    """Prints the menu"""
    MENU = f"""----------- Database Encryption Menu -------------

> Note: Please only re-encrypt the database 
        when the server is in maintenance mode
        and when there is a key rotation!

1. Re-encrypt database
X. Close program

--------------------------------------------------"""
    print(MENU)

"""----------------------------------- END OF DEFINING FUNCTIONS -----------------------------------"""

AVAILABLE_OPTIONS = ("1", "x")
NUMBER_REGEX = re.compile(r"^\d+$")

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        print()
        debugFlag = True if (debugPrompt != "n") else False
        break

def main() -> None:
    while (1):
        # count number of existing admin accounts
        print_menu()

        cmdOption = input("Enter option: ").lower().strip()
        if (cmdOption not in AVAILABLE_OPTIONS):
            print("Invalid input", end="\n\n")
            continue
        elif (cmdOption == "1"):
            while (1):
                confirmPrompt = input("Are you sure you want to re-encrypt the database? (y/N): ").lower().strip()
                if (confirmPrompt not in ("y", "n", "")):
                    print("Invalid input", end="\n\n")
                    continue
                else:
                    continueFlag = True if (confirmPrompt == "y") else False
                    break

            if (continueFlag):
                print("Re-encrypting database...", end="")
                try:
                    con = NormalFunctions.get_mysql_connection(debug=debugFlag)
                except (pymysql.ProgrammingError):
                    print("\nDatabase Not Found. Please create one first")
                    sysExit(1)

                cur = con.cursor()
                cur.execute("SELECT u.id, u.password, tfa.token, tfa.backup_codes_json FROM user AS u LEFT OUTER JOIN twofa_token AS tfa ON u.id=tfa.user_id;")

                errorInfo = {}
                for row in cur.fetchall():
                    userID = row[0]

                    # Re-encrypt the password hash if the user has signed up
                    # via CourseFinity and not via Google OAuth2
                    currentEncryptedPasswordHash = row[1]
                    if (currentEncryptedPasswordHash is not None):
                        try:
                            newEncryptedPasswordHash = NormalFunctions.symmetric_encrypt(
                                plaintext=NormalFunctions.symmetric_decrypt(
                                    ciphertext=currentEncryptedPasswordHash,
                                    keyID=CONSTANTS.PEPPER_KEY_ID
                                ),
                                keyID=CONSTANTS.PEPPER_KEY_ID
                            )
                        except (NormalFunctions.DecryptionError):
                            NormalFunctions.write_log_entry(
                                logMessage=f"Re-encryption of password hash has failed...",
                                severity="ALERT"
                            )
                            errorInfo = {"has_error": True, "error": "decryption Error with password hash"}
                            break
                        cur.execute(
                            "UPDATE user SET password = %(password)s WHERE id=%(userID)s",
                            {"password":newEncryptedPasswordHash, "userID":userID}
                        )
                        con.commit()

                    # Re-encrypt the 2FA token if the user has set one
                    oldEncryptedTwoFAToken = row[2]
                    if (oldEncryptedTwoFAToken is not None):
                        try:
                            newEncryptedToken = NormalFunctions.symmetric_encrypt(
                                plaintext=NormalFunctions.symmetric_decrypt(
                                    ciphertext=oldEncryptedTwoFAToken,
                                    keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                                ),
                                keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                            )
                        except (NormalFunctions.DecryptionError):
                            NormalFunctions.write_log_entry(
                                logMessage="Re-encryption of 2FA token has failed...",
                                severity="ALERT"
                            )
                            errorInfo = {"has_error": True, "error": "decryption Error with 2FA tokens"}
                            break
                        cur.execute(
                            "UPDATE twofa_token SET token = %(token)s WHERE user_id=%(userID)s",
                            {"token":newEncryptedToken, "userID":userID}
                        )
                        con.commit()

                    # Re-encrypt the backup codes if the user has set up 2FA
                    oldEncryptedBackupCodes = row[3]
                    if (oldEncryptedBackupCodes is not None):
                        try:
                            newEncryptedBackupCodes = NormalFunctions.symmetric_encrypt(
                                plaintext=NormalFunctions.symmetric_decrypt(
                                    ciphertext=oldEncryptedBackupCodes,
                                    keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                                ),
                                keyID=CONSTANTS.SENSITIVE_DATA_KEY_ID
                            )
                        except (NormalFunctions.DecryptionError):
                            NormalFunctions.write_log_entry(
                                logMessage="Re-encryption of backup codes has failed...",
                                severity="ALERT"
                            )
                            errorInfo = {"has_error": True, "error": "decryption Error with backup codes"}
                            break
                        cur.execute(
                            "UPDATE twofa_token SET backup_codes_json = %(backupCodes)s WHERE user_id=%(userID)s",
                            {"backupCodes":newEncryptedBackupCodes, "userID":userID}
                        )
                        con.commit()

                if (errorInfo.get("has_error", False)):
                    NormalFunctions.write_log_entry(
                        logMessage=f"All sensitive user data was being re-encrypted in the database at {datetime.now().astimezone(tz=ZoneInfo('Asia/Singapore'))}, but had {errorInfo['error']}.",
                        severity="EMERGENCY"
                    )
                    print("\r\033[KRe-encryption failed.")
                    print("Error:", errorInfo["error"])
                    print("Please contact the system administrator.")
                else:
                    NormalFunctions.write_log_entry(
                        logMessage=f"All sensitive user data have re-encrypted in the database at {datetime.now().astimezone(tz=ZoneInfo('Asia/Singapore'))}, please consider destroying the old symmetric keys used for the database as soon as possible if no longer in use!",
                        severity="ALERT"
                    )
                    print("\r\033[KAll sensitive user data have been re-encrypted in the database!\n")
            else:
                print("Re-encryption cancelled\n")

        elif (cmdOption == "x"):
            con.close()
            shutdown()

try:
    main()
except (KeyboardInterrupt):
    shutdown()