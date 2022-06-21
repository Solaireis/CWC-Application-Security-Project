# import third party libraries
import mysql.connector

# import python standard libraries
from os import environ

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants import LOCAL_SQL_SERVER_CONFIG, REMOTE_SQL_SERVER_CONFIG, DATABASE_NAME
else:
    from .Constants import LOCAL_SQL_SERVER_CONFIG, REMOTE_SQL_SERVER_CONFIG, DATABASE_NAME

def delete_mysql_database(debug:bool=False) -> None:
    """
    Delete the database (run this if you want to reset the database)

    Args:
        debug (bool): If true, will delete locally, else will delete remotely
    """
    if (debug):
        config = LOCAL_SQL_SERVER_CONFIG.copy()
    else:
        config = REMOTE_SQL_SERVER_CONFIG.copy()

    config["database"] = DATABASE_NAME
    mydb = mysql.connector.connect(**config)
    cur = mydb.cursor()

    cur.execute("DROP DATABASE coursefinity")
    mydb.commit()
    mydb.close()

if (__name__ == "__main__"):
    while (1):
        debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
        if (debugPrompt not in ("y", "n", "")):
            print("Invalid input", end="\n\n")
            continue
        else:
            debugFlag = True if (debugPrompt != "n") else False
            break

    try:
        delete_mysql_database(debug=debugFlag)
        print("Deleted the database, \"coursefinity\"...")
    except (mysql.connector.errors.DatabaseError):
        print("Error: Database \"coursefinity\" does not exist...")