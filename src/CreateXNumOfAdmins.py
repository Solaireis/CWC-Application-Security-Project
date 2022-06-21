from argon2 import PasswordHasher as PH
import mysql.connector
from os import environ
from python_files.NormalFunctions import generate_id
from sys import exit as sysExit
import re
from python_files.NormalFunctions import symmetric_encrypt

NUMBER_REGEX = re.compile(r"^\d+$")
MAX_NUMBER_OF_ADMINS = 10 # try not to increase the limit too much, otherwise you pay for the Google Cloud :prayge:

# while (1):
#     debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
#     if (debugPrompt not in ("y", "n", "")):
#         print("Invalid input", end="\n\n")
#         continue
#     else:
#         debugFlag = True if (debugPrompt != "n") else False
#         break

# if (debugFlag):
#     host = "localhost"
#     password = environ["LOCAL_SQL_PASS"]
# else:
#     host = environ["GOOGLE_CLOUD_MYSQL_SERVER"] # Google Cloud SQL Public address
#     password = environ["REMOTE_SQL_PASS"]

host = "localhost"
password = environ["LOCAL_SQL_PASS"]
try:
    con = mysql.connector.connect(
        host=host,
        user="root",
        password=password,
        database="coursefinity",
    )
except (mysql.connector.errors.ProgrammingError):
    print("Database Not Found. Please create one first")
    sysExit(1)
cur = con.cursor(buffered=True)

# convert role name to role id
ADMIN_ROLE_ID = None
cur.callproc("get_role_id", ("Admin",))
for result in cur.stored_results():
    ADMIN_ROLE_ID = result.fetchone()[0]

if (ADMIN_ROLE_ID is None):
    print("Error: Role not found")
    con.close()
    sysExit(1)

MENU = """----------- Menu (Debug Mode) -------------

> Note: This is only for DEBUG purposes.

1. Create X number of admins
2. Delete all admins
X. Close program

-------------------------------------------"""
AVAILABLE_OPTIONS = ("1", "2", "x")

def main() -> None:
    while (1):
        print(MENU)
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
                    noOfAdmin = int(noOfAdmin) % MAX_NUMBER_OF_ADMINS
                    print(f"Creating {noOfAdmin} admins...")
                    break

            # count number of existing admin accounts
            cur.execute("SELECT COUNT(*) FROM user WHERE role = %(roleID)s", {"roleID": ADMIN_ROLE_ID})
            existingAdminCount = cur.fetchone()[0]

            if (existingAdminCount >= MAX_NUMBER_OF_ADMINS):
                count = 0
                profilePic = "/static/images/user/default.png"
                for i in range(noOfAdmin - existingAdminCount):
                    adminID = generate_id()
                    username = f"Admin-{i}"
                    email = f"admin{i}@coursefinity.com"
                    keyName = "test-key"
                    # for debug purposes only (in real world use, use a more secure password)
                    password = symmetric_encrypt(plaintext=PH().hash("Admin123!"), keyID=keyName)

                    cur.execute(
                        "INSERT INTO user (id, role, username, email, password, profile_image, key_name) VALUES (%(id)s, %(role)s, %(username)s, %(email)s, %(password)s, %(profilePic)s, %(keyName)s)", \
                        {"id": adminID, "role": ADMIN_ROLE_ID, "username": username, "email": email, "password": password, "profilePic": profilePic, "keyName": keyName}
                    )
                    count += 1
                con.commit()
                print(f"{count} admin accounts created!")
            else:
                print(f"Maximum number of {MAX_NUMBER_OF_ADMINS} admin accounts already exists!")
            print()

        elif (cmdOption == "2"):
            cur.execute("DELETE FROM user WHERE role = %(roleID)s", {"roleID": ADMIN_ROLE_ID})
            con.commit()
            print("All admin accounts deleted!\n")

        elif (cmdOption == "x"):
            con.close()
            print()
            print("Shutting down...")
            input("Please press ENTER to exit...")
            sysExit(0)

if (__name__ == "__main__"):
    main()