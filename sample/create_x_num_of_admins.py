# import third party libraries
import pymysql
from email_validator import validate_email, EmailNotValidError

# import python standard libraries
from sys import exit as sysExit
import re, pathlib, sys
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
    """
    For UX, prints shutdown message.
    """
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")
    sysExit(0)

def print_menu(adminCount:int=0) -> None:
    """
    Prints the menu
    
    Args
    - adminCount (int): Number of admin accounts in the database.
    """
    MENU = f"""----------- Menu (Debug Mode) -------------

> Note: This is only for DEBUG purposes.
> Admin Count: {adminCount}

1. Create X number of admins (Login not supported)
2. Create X number of admins (Login supported)
3. Delete all admins
X. Close program

-------------------------------------------"""
    print(MENU)

def enter_email() -> str:
    """Validates email input and returns the validated email address."""
    while (1):
        emailInput = input("Enter Email (x to cancel): ").strip().lower()
        if (emailInput == "x"):
            return "x"
        try:
            return validate_email(emailInput).email
        except (EmailNotValidError) as e:
            print(f"Invalid email Error: {e}", end="\n\n")
            continue

"""----------------------------------- END OF DEFINING FUNCTIONS -----------------------------------"""

AVAILABLE_OPTIONS = ("1", "2", "x")
NUMBER_REGEX = re.compile(r"^\d+$")
MAX_NUMBER_OF_ADMINS = 10 # try not to increase the limit too much

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        print()
        debugFlag = True if (debugPrompt != "n") else False
        break

try:
    con = NormalFunctions.get_mysql_connection(debug=debugFlag)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")
    sysExit(1)
cur = con.cursor()

# convert role name to role id
ADMIN_ROLE_ID = None
cur.execute("CALL get_role_id('Admin')")
ADMIN_ROLE_ID = cur.fetchone()

if (ADMIN_ROLE_ID is None):
    print("Error: Role not found")
    con.close()
    sysExit(1)

ADMIN_ROLE_ID = ADMIN_ROLE_ID[0]

def main() -> None:
    while (1):
        # count number of existing admin accounts
        cur.execute("SELECT COUNT(*) FROM user WHERE role = %(roleID)s", {"roleID": ADMIN_ROLE_ID})
        existingAdminCount = cur.fetchone()[0]
        print_menu(adminCount=existingAdminCount)

        cmdOption = input("Enter option: ").lower().strip()
        if (cmdOption not in AVAILABLE_OPTIONS):
            print("Invalid input", end="\n\n")
            continue
        elif (cmdOption == "1" or cmdOption == "2"):
            noOfAdmin = 1
            while (1 and cmdOption == "1"):
                print()
                print("Note: The maximum number of admins in the database is 10!")
                noOfAdmin = input("Number of admins to create: ")
                if (not re.fullmatch(NUMBER_REGEX, noOfAdmin)):
                    print("Please enter a number!", end="\n\n")
                    continue
                else:
                    try:
                        noOfAdmin = int(noOfAdmin)
                        differences = MAX_NUMBER_OF_ADMINS - existingAdminCount
                        if (noOfAdmin > differences):
                            noOfAdmin = differences
                    except (ZeroDivisionError):
                        noOfAdmin = 0
                    print(f"\nCreating {noOfAdmin} admins...")
                    break

            if (existingAdminCount < MAX_NUMBER_OF_ADMINS):
                count = 0
                profilePic = "https://storage.googleapis.com/coursefinity/user-profiles/default.png"
                for i in range(existingAdminCount, noOfAdmin + existingAdminCount):
                    adminID = NormalFunctions.generate_id()
                    username = f"Admin-{i}"
                    emailInput = ""
                    if (cmdOption == "1"):
                        emailInput = f"admin{i}@coursefinity.com"
                    else:
                        while (1):
                            emailInput = enter_email()
                            if (emailInput == "x"):
                                break

                            # check for duplicates
                            cur.execute("SELECT * FROM user WHERE email = %(email)s", {"email": emailInput})
                            if (cur.fetchone() is not None):
                                print("Error: Email already exists!", end="\n\n")
                                continue

                            # confirm prompt
                            while (1):
                                print(f"\nAre you sure that you want to use the email, {emailInput}?")
                                confirmPrompt = input("Confirm (Y/n/x to go back to menu): ").lower().strip()
                                if (confirmPrompt not in ("y", "n", "x", "")):
                                    print("Invalid input", end="\n\n")
                                    continue
                                break
                            # "x" to stop adding admins and break out of the enter email loop
                            if (confirmPrompt == "x"):
                                emailInput = confirmPrompt
                                break
                            confirmPrompt = True if (confirmPrompt != "n") else False
                            if (confirmPrompt):
                                break # break out of while (1) loop if user confirms the input

                        # "x" to stop adding admins and break out of the for loop
                        if (emailInput == "x"):
                            break

                    cur.execute(
                        "INSERT INTO user (id, role, username, email, email_verified, profile_image, date_joined) VALUES (%(id)s, %(role)s, %(username)s, %(email)s, 1, %(profilePic)s, SGT_NOW())", \
                        {"id": adminID, "role": ADMIN_ROLE_ID, "username": username, "email": emailInput, "profilePic": profilePic}
                    )
                    con.commit()
                    count += 1

                print(f"\n{count} admin accounts created!")
            else:
                print(f"\nMaximum number of {MAX_NUMBER_OF_ADMINS} admin accounts already exists!")
            print()

        elif (cmdOption == "3"):
            # delete data of all admins
            cur.execute("SELECT id FROM user WHERE role = %(roleID)s", {"roleID": ADMIN_ROLE_ID})
            listOfAdmins = cur.fetchall()
            listOfAdmins = [adminID[0] for adminID in listOfAdmins]
            for adminID in listOfAdmins:
                cur.execute("CALL delete_user(%(adminID)s)", {"adminID": adminID})

            con.commit()
            print("All admin accounts deleted!\n")

        elif (cmdOption == "x"):
            con.close()
            shutdown()

try:
    main()
except (KeyboardInterrupt):
    con.close()
    shutdown()