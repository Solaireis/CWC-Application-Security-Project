# import third party libraries
import pymysql
from randomuser import RandomUser

# import python standard libraries
from sys import exit as sysExit
import re, pathlib, sys
from importlib.util import spec_from_file_location, module_from_spec
from socket import inet_aton, inet_pton, AF_INET6

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

def print_menu(userCount:int=0) -> None:
    """
    Prints the menu
    
    Args
    - adminCount (int): Number of admin accounts in the database.
    """
    MENU = f"""----------- Menu (Debug Mode) -------------

> Note: This is only for DEBUG purposes.
> User Count: {userCount}

1. Create X number of students
2. Delete all users (Except admins)
X. Close program

-------------------------------------------"""
    print(MENU)

"""----------------------------------- END OF DEFINING FUNCTIONS -----------------------------------"""

AVAILABLE_OPTIONS = ("1", "2", "x")
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

try:
    con = NormalFunctions.get_mysql_connection(debug=debugFlag)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")
    sysExit(1)
cur = con.cursor()

# convert role name to role id
STUDENT_ROLE_ID = None
cur.execute("CALL get_role_id('Student')")
STUDENT_ROLE_ID = cur.fetchone()

# convert role name to role id
ADMIN_ROLE_ID = None
cur.execute("CALL get_role_id('Admin')")
ADMIN_ROLE_ID = cur.fetchone()

if (STUDENT_ROLE_ID is None or ADMIN_ROLE_ID is None):
    print("Error: Role not found")
    con.close()
    sysExit(1)

STUDENT_ROLE_ID = STUDENT_ROLE_ID[0]
ADMIN_ROLE_ID = ADMIN_ROLE_ID[0]

def main() -> None:
    while (1):
        # count number of existing admin accounts
        cur.execute("SELECT COUNT(*) FROM user WHERE role <> %(roleID)s", {"roleID": ADMIN_ROLE_ID})
        existingUserCount = cur.fetchone()[0]
        print_menu(userCount=existingUserCount)

        cmdOption = input("Enter option: ").lower().strip()
        if (cmdOption not in AVAILABLE_OPTIONS):
            print("Invalid input", end="\n\n")
            continue
        elif (cmdOption == "1"):
            noOfStudents = 0
            while (1):
                print()
                noOfStudents = input("Number of students to create: ")
                if (not re.fullmatch(NUMBER_REGEX, noOfStudents)):
                    print("Please enter a number!", end="\n\n")
                    continue
                else:
                    noOfStudents = int(noOfStudents)
                    print(f"\nCreating {noOfStudents} students...", end="")
                    break

            count = 0
            for _ in range(noOfStudents):
                randomStudentInfo = RandomUser(get_params={"nat": "AU,CA,US"})
                userID = NormalFunctions.generate_id()
                username = randomStudentInfo.get_full_name()
                email = randomStudentInfo.get_email()
                # for debug purposes only (in real world use, use a more secure password)
                password = NormalFunctions.symmetric_encrypt(plaintext=CONSTANTS.PH.hash("User123!"), keyID=CONSTANTS.PEPPER_KEY_ID)

                cur.execute(
                    "INSERT INTO user (id, role, username, email, email_verified, password, profile_image, date_joined) VALUES (%(id)s, %(role)s, %(username)s, %(email)s, 1, %(password)s, %(profilePic)s, SGT_NOW())", \
                    {"id": userID, "role": STUDENT_ROLE_ID, "username": username, "email": email, "password": password, "profilePic": randomStudentInfo.get_picture()}
                )
                con.commit()

                ipAddress = "127.0.0.1"

                # Convert the IP address to binary format
                try:
                    ipAddress = inet_aton(ipAddress).hex()
                    isIpv4 = True
                except (OSError):
                    isIpv4 = False
                    ipAddress = inet_pton(AF_INET6, ipAddress).hex()

                cur.execute("INSERT INTO user_ip_addresses (user_id, last_accessed, ip_address, is_ipv4) VALUES (%(userID)s, SGT_NOW(), %(ipAddress)s, %(isIpv4)s)", {"userID": userID, "ipAddress": ipAddress, "isIpv4": isIpv4})
                con.commit()

                count += 1

            print(f"\r{count} student accounts created!")
            print()

        elif (cmdOption == "2"):
            # delete data of all users except admins
            cur.execute("SELECT id FROM user WHERE role <> %(roleID)s", {"roleID": ADMIN_ROLE_ID})
            userArr = cur.fetchall()
            userArr = [userID[0] for userID in userArr]
            for userID in userArr:
                cur.execute("CALL delete_user(%(userID)s)", {"userID": userID})

            con.commit()
            print("All user accounts deleted!\n")

        elif (cmdOption == "x"):
            con.close()
            shutdown()

try:
    main()
except (KeyboardInterrupt):
    con.close()
    shutdown()