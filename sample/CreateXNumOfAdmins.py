# import third party libraries
import pymysql

# import python standard libraries
from sys import exit as sysExit
import re, pathlib
import sys
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "python_files")

# add to sys path so that Constants.py can be imported by NormalFunctions.py
sys.path.append(str(PYTHON_FILES_PATH))

# import NormalFunctions.py local python module using absolute path
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("NormalFunctions.py")
spec = spec_from_file_location("NormalFunctions", str(NORMAL_PY_FILE))
NormalFunctions = module_from_spec(spec)
sys.modules[spec.name] = NormalFunctions
spec.loader.exec_module(NormalFunctions)

# Import MySQLInit.py for get_msql_connection() function
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("MySQLInit.py")
spec = spec_from_file_location("MySQLInit", str(NORMAL_PY_FILE))
MySQLInit = module_from_spec(spec)
sys.modules[spec.name] = MySQLInit
spec.loader.exec_module(MySQLInit)

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

1. Create X number of admins
2. Delete all admins
X. Close program

-------------------------------------------"""
    print(MENU)

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
    con = MySQLInit.get_mysql_connection(debug=debugFlag)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")
    sysExit(1)
cur = con.cursor()

# convert role name to role id
ADMIN_ROLE_ID = None
cur.execute("CALL get_role_id(%(Admin)s)", {"Admin":"Admin"})
ADMIN_ROLE_ID = cur.fetchone()[0]

if (ADMIN_ROLE_ID is None):
    print("Error: Role not found")
    con.close()
    sysExit(1)

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
        elif (cmdOption == "1"):
            noOfAdmin = 0
            while (1):
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
                    print(f"\nCreating {noOfAdmin} admins...", end="")
                    break

            if (existingAdminCount < MAX_NUMBER_OF_ADMINS):
                count = 0
                profilePic = "/static/images/user/default.png"
                for i in range(existingAdminCount, noOfAdmin + existingAdminCount):
                    adminID = NormalFunctions.generate_id()
                    username = f"Admin-{i}"
                    email = f"admin{i}@coursefinity.com"
                    # for debug purposes only (in real world use, use a more secure password)
                    password = NormalFunctions.symmetric_encrypt(plaintext=CONSTANTS.PH.hash("Admin123!"), keyID=CONSTANTS.PEPPER_KEY_ID)

                    cur.execute(
                        "INSERT INTO user (id, role, username, email, password, profile_image, date_joined) VALUES (%(id)s, %(role)s, %(username)s, %(email)s, %(password)s, %(profilePic)s, SGT_NOW())", \
                        {"id": adminID, "role": ADMIN_ROLE_ID, "username": username, "email": email, "password": password, "profilePic": profilePic}
                    )
                    con.commit()

                    cur.execute("INSERT INTO user_ip_addresses (user_id, last_accessed, ip_address) VALUES (%(adminID)s, SGT_NOW(), %(ipAddress)s)", {"adminID": adminID, "ipAddress": "127.0.0.1"})
                    con.commit()

                    count += 1

                existingAdminCount += count
                print(f"\r{count} admin accounts created!")
            else:
                print(f"\rMaximum number of {MAX_NUMBER_OF_ADMINS} admin accounts already exists!")
            print()

        elif (cmdOption == "2"):
            # delete ip address data of all admins (due to foriegn key constraints)
            cur.execute("SELECT id FROM user WHERE role = %(roleID)s", {"roleID": ADMIN_ROLE_ID})
            listOfAdmins = cur.fetchall()
            listOfAdmins = [adminID[0] for adminID in listOfAdmins]
            for adminID in listOfAdmins:
                cur.execute("DELETE FROM session WHERE user_id = %(adminID)s", {"adminID": adminID})
                cur.execute("DELETE FROM user_ip_addresses WHERE user_id = %(userID)s", {"userID": adminID})

            cur.execute("DELETE FROM user WHERE role = %(roleID)s", {"roleID": ADMIN_ROLE_ID})
            con.commit()
            print("All admin accounts deleted!\n")
            existingAdminCount = 0

        elif (cmdOption == "x"):
            con.close()
            shutdown()

try:
    main()
except (KeyboardInterrupt):
    con.close()
    shutdown()