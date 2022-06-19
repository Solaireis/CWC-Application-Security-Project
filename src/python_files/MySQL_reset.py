import mysql.connector
from os import environ

def delete_mysql_database(debug:bool=False) -> None:
    """
    Delete the database (run this if you want to reset the database)

    Args:
        debug (bool): If true, will delete locally, else will delete remotely
    """
    if (debug):
        host = "localhost"
        password = environ["LOCAL_SQL_PASS"]
    else:
        host = environ["GOOGLE_CLOUD_MYSQL_SERVER"] # Google Cloud SQL Public address
        password = environ["REMOTE_SQL_PASS"]

    mydb = mysql.connector.connect(
        host=host,
        user="root",
        password=password
    )

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

    delete_mysql_database(debug=debugFlag)
    print("Deleted the database, \"coursefinity\"...")