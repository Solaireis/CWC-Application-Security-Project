# import third party libraries
import pymysql

# import local python libraries
if (__package__ is None or __package__ == ""):
    from MySQLInit import get_mysql_connection
else:
    from .MySQLInit import get_mysql_connection

def delete_mysql_database(debug:bool=False) -> None:
    """
    Delete the database (run this if you want to reset the database)

    Args:
    - debug (bool): If true, will delete locally, else will delete remotely
    """
    mydb = get_mysql_connection(debug=debug)
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
    except (pymysql.err.DatabaseError) as e:
        print(e)
        print("Error: Database \"coursefinity\" does not exist...")