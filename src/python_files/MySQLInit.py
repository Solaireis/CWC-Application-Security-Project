# import third party libraries
import pymysql

# import python standard libraries
from typing import Optional

# import local python libraries
if (__package__ is None or __package__ == ""):
    from Constants import CONSTANTS
else:
    from .Constants import CONSTANTS

def get_mysql_connection(debug:bool=CONSTANTS.DEBUG_MODE, database:Optional[str]=CONSTANTS.DATABASE_NAME) -> pymysql.connections.Connection:
    """
    Get a MySQL connection to the coursefinity database.
    
    Args:
    - debug (bool): whether to connect to the MySQL database locally or to Google CLoud SQL Server
        - Defaults to DEBUG_MODE defined in Constants.py
    - database (str, optional): the name of the database to connect to
        - Defaults to DATABASE_NAME defined in Constants.py if not defined
        - Define database to None if you do not want to connect to a database
    
    Returns:
    A MySQL connection.
    """
    if (debug):
        LOCAL_SQL_CONFIG_COPY = CONSTANTS.LOCAL_SQL_SERVER_CONFIG.copy()
        if (database is not None):
            LOCAL_SQL_CONFIG_COPY["database"] = database
        connection = pymysql.connect(**LOCAL_SQL_CONFIG_COPY)
        return connection
    else:
        connection: pymysql.connections.Connection = CONSTANTS.SQL_CLIENT.connect(
            instance_connection_string=CONSTANTS.SQL_INSTANCE_LOCATION,
            driver="pymysql",
            user="root",
            password=CONSTANTS.get_secret_payload(secretID="sql-root-password"),
            database=database
        )
        return connection

def mysql_init_tables(debug:bool=False) -> pymysql.connections.Connection:
    """
    Initialize the database with the necessary tables

    Args:
    - debug (bool): If true, will initialise locally, else will initialise remotely
    
    Returns:
    - The connection to the database (mysql connection object)
    """
    if (debug):
        definer = "root`@`localhost"
    else:
        definer = f"root`@`{CONSTANTS.REMOTE_SQL_SERVER_IP}"

    mydb = get_mysql_connection(debug=debug, database=None)
    cur = mydb.cursor()

    cur.execute("CREATE DATABASE coursefinity")
    mydb.commit()
    mydb.close()

    mydb = get_mysql_connection(debug=debug)
    cur = mydb.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS role (
        role_id INTEGER UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        role_name VARCHAR(255) NOT NULL UNIQUE
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id VARCHAR(32) PRIMARY KEY, 
        role INTEGER UNSIGNED NOT NULL,
        username VARCHAR(255) NOT NULL UNIQUE, 
        email VARCHAR(255) NOT NULL UNIQUE, 
        password VARBINARY(1024) DEFAULT NULL, -- can be null for user who signed in using Google OAuth2
        profile_image VARCHAR(255) DEFAULT NULL, 
        date_joined DATETIME NOT NULL,
        key_name VARCHAR(36) NOT NULL,
        cart_courses JSON DEFAULT NULL, -- can be null for admin user
        purchased_courses JSON DEFAULT NULL, -- can be null for admin user
        FOREIGN KEY (role) REFERENCES role(role_id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS course (
        course_id CHAR(32) PRIMARY KEY, 
        teacher_id VARCHAR(32) NOT NULL,
        course_name VARCHAR(255) NOT NULL,
        course_description VARCHAR(255) DEFAULT NULL,
        course_image_path VARCHAR(255) DEFAULT NULL,
        course_price DECIMAL(6,2) NOT NULL, -- up to 6 digits, 2 decimal places (max: $9999.99)
        course_category VARCHAR(255) NOT NULL,
        course_total_rating INTEGER UNSIGNED NOT NULL DEFAULT 0,
        course_rating_count INTEGER UNSIGNED NOT NULL DEFAULT 0,
        date_created DATETIME NOT NULL,
        video_path VARCHAR(255) NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS user_ip_addresses (
        user_id VARCHAR(32) NOT NULL,
        ip_address VARBINARY(16) NOT NULL,
        last_accessed DATETIME NOT NULL,
        ip_address_details VARCHAR(1024) DEFAULT NULL,
        PRIMARY KEY (user_id, ip_address),
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS twofa_token (
        token VARBINARY(512) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        user_id VARCHAR(32) PRIMARY KEY,
        attempts INTEGER UNSIGNED NOT NULL,
        reset_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS session (
        session_id CHAR(32) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        expiry_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id VARCHAR(32),
        course_id CHAR(32),
        course_rating INTEGER UNSIGNED,
        course_review VARCHAR(255),
        review_date DATETIME NOT NULL,
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (course_id) REFERENCES course(course_id)
    )""")

    # cur.execute("""CREATE TABLE IF NOT EXISTS cart (
    #     user_id VARCHAR(32),
    #     course_id CHAR(32),
    #     PRIMARY KEY (user_id, course_id),
    #     FOREIGN KEY (user_id) REFERENCES user(id),
    #     FOREIGN KEY (course_id) REFERENCES course(course_id)
    # )""")

    # cur.execute("""CREATE TABLE IF NOT EXISTS purchased (
    #     user_id VARCHAR(32),
    #     course_id CHAR(32),
    #     PRIMARY KEY (user_id, course_id),
    #     FOREIGN KEY (user_id) REFERENCES user(id),
    #     FOREIGN KEY (course_id) REFERENCES course(course_id)
    # )""")

    # end of table creation
    mydb.commit()

    # Stored Procedures
    """Template"""
    # cur.execute("""
    #     CREATE DEFINER=%(definer)s PROCEDURE `procedurename`(arguments)
    #     BEGIN
    #         query statement;
    #     END
    # """, {"definer":definer})
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `get_role_name`(IN roleID INT UNSIGNED)
        BEGIN
            SELECT role_name FROM role WHERE role_id=roleID;
        END
        """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `get_role_id`(IN roleName VARCHAR(255))
        BEGIN
            SELECT role_id FROM role WHERE role_name=roleName;
        END
        """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `search_for`(IN search_term VARCHAR(255))
        BEGIN
            SELECT course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, date_created, course_total_rating, course_rating_count FROM course WHERE course_name LIKE CONCAT('%', search_term , '%');
        END
    """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` FUNCTION SGT_NOW() RETURNS DATETIME 
        DETERMINISTIC 
        COMMENT 'Returns SGT (UTC+8) datetime.'
        BEGIN
            RETURN CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+08:00');
        END
    """)

    # end of stored procedures
    mydb.commit()

    # data initialisation
    cur.execute("INSERT INTO role (role_name) VALUES ('Student')")
    mydb.commit()

    cur.execute("INSERT INTO role (role_name) VALUES ('Teacher')")
    mydb.commit()

    cur.execute("INSERT INTO role (role_name) VALUES ('Admin')")
    mydb.commit()

    return mydb

if (__name__ == "__main__"):
    while (1):
        debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
        if (debugPrompt not in ("y", "n", "")):
            print("Invalid input", end="\n\n")
            continue
        else:
            debugFlag = True if (debugPrompt != "n") else False
            break

    from MySQLReset import delete_mysql_database
    try:
        mysql_init_tables(debug=debugFlag)
        print("Successfully initialised the tables in the database, \"coursefinity\"!")
    except (pymysql.err.ProgrammingError) as e:
        print("\nSyntax error caught!")
        print("More details:")
        print(e)

        delete_mysql_database(debug=debugFlag)
        print("\nDeleted all tables as there was a syntax error in the schema.")
    except (Exception) as e:
        print("\nDatabase error caught!")
        print("More details:")
        print(e)

        delete_mysql_database(debug=debugFlag)
        print("\nDeleted all tables as there was a database error in the schema.")