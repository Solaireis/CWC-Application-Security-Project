import mysql.connector
from os import environ

def mysql_init_tables(debug:bool=False) -> mysql.connector.connection.MySQLConnection:
    """
    Initialize the database with the necessary tables

    Args:
        debug (bool): If true, will initialise locally, else will initialise remotely
    
    Returns:
        The connection to the database (mysql connection object)
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

    definer = f"root`@`{host}"

    cur = mydb.cursor()
    cur.execute("CREATE DATABASE coursefinity")
    mydb.commit()

    mydb.close()

    mydb = mysql.connector.connect(
        host=host,
        user="root",
        password=password,
        database="coursefinity"
    )
    cur = mydb.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS role (
        role_id INTEGER UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        role_name VARCHAR(255) NOT NULL UNIQUE
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id VARCHAR(32) PRIMARY KEY, 
        role INT UNSIGNED NOT NULL,
        username VARCHAR(255) NOT NULL UNIQUE, 
        email VARCHAR(255) NOT NULL UNIQUE, 
        password VARBINARY(1024), -- can be null for user who signed in using Google OAuth2
        profile_image VARCHAR(255), 
        date_joined DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        card_name VARCHAR(255),
        card_no INTEGER UNSIGNED, -- May not be unique since one might have alt accounts.
        card_exp VARCHAR(255),
        key_name CHAR(36) NOT NULL,
        cart_courses VARCHAR(255), -- can be null for normal user
        purchased_courses VARCHAR(255), -- can be null for normal user
        FOREIGN KEY (role) REFERENCES role(role_id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS course (
        course_id CHAR(32) PRIMARY KEY, 
        teacher_id VARCHAR(32) NOT NULL,
        course_name VARCHAR(255) NOT NULL,
        course_description VARCHAR(255),
        course_image_path VARCHAR(255),
        course_price DECIMAL(6,2) NOT NULL, -- up to 6 digits, 2 decimal places (max: $9999.99)
        course_category VARCHAR(255) NOT NULL,
        course_total_rating INTEGER NOT NULL,
        course_rating_count INTEGER NOT NULL,
        date_created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        video_path VARCHAR(255) NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS user_ip_addresses (
        user_id VARCHAR(32) NOT NULL,
        ip_address VARBINARY(16) NOT NULL,
        PRIMARY KEY (user_id, ip_address),
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS twofa_token (
        token VARBINARY(92) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        user_id VARCHAR(32) PRIMARY KEY,
        attempts INTEGER NOT NULL,
        reset_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS session (
        session_id CHAR(32) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        expiry_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS cart (
        user_id VARCHAR(32),
        course_id CHAR(32),
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (course_id) REFERENCES course(course_id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS purchased (
        user_id VARCHAR(32),
        course_id CHAR(32),
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (course_id) REFERENCES course(course_id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id VARCHAR(32),
        course_id CHAR(32),
        course_rating INTEGER,
        review_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (course_id) REFERENCES course(course_id)
    )""")

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

    from MySQL_reset import delete_mysql_database
    try:
        mysql_init_tables(debug=debugFlag)
        print("Successfully initialised the tables in the database, \"coursefinity\"!")
    except (mysql.connector.errors.ProgrammingError) as e:
        print("\nSyntax error caught!")
        print("More details:")
        print(e)

        delete_mysql_database(debug=debugFlag)
        print("\nDeleted all tables as there was a syntax error in the schema.")
    except (mysql.connector.errors.DatabaseError) as e:
        print("\nDatabase error caught!")
        print("More details:")
        print(e)

        delete_mysql_database(debug=debugFlag)
        print("\nDeleted all tables as there was a database error in the schema.")