# import third party libraries
import pymysql.cursors

# import local python libraries
from datetime import datetime
from random import randint
import pathlib, uuid
from sys import modules
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries using absolute paths
FILE_PATH = pathlib.Path(__file__).parent.absolute()

# import Constants_Init.py local python module using absolute path
CONSTANTS_INIT_PY_FILE = FILE_PATH.parent.joinpath("src", "python_files", "ConstantsInit.py")
spec = spec_from_file_location("Constants_Init", str(CONSTANTS_INIT_PY_FILE))
Constants_Init = module_from_spec(spec)
modules[spec.name] = Constants_Init
spec.loader.exec_module(Constants_Init)

"""----------------------------------- START OF DEFINING FUNCTIONS -----------------------------------"""

def generate_id() -> str:
    """
    Generates a unique ID (32 bytes)
    """
    return uuid.uuid4().hex

"""----------------------------------- START OF DEFINING FUNCTIONS -----------------------------------"""

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        debugFlag = True if (debugPrompt != "n") else False
        break

if (debugFlag):
    config = Constants_Init.LOCAL_SQL_SERVER_CONFIG.copy()
else:
    config = Constants_Init.REMOTE_SQL_SERVER_CONFIG.copy()

config["database"] = Constants_Init.DATABASE_NAME
try:
    con = pymysql.connect(**config)
except (pymysql.ProgrammingError):
    print("Database Not Found. Please create one first")
cur = con.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id VARCHAR(255),
        course_id VARCHAR(255),
        course_rating INTEGER UNSIGNED,
        course_review VARCHAR(255),
        
        PRIMARY KEY (user_id, course_id)
    )""")

