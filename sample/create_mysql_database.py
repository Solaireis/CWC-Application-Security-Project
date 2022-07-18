"""
For development purposes, to be removed from any imports during production environment.
"""
# import third party libraries
import pymysql
import stripe
from stripe.error import InvalidRequestError

# import python standard libraries
import pathlib, sys, json
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
stripe.api_key = CONSTANTS.STRIPE_SECRET_KEY

def deactivate_stripe_courses(debug:bool=False) -> None:
    """
    Deactivate stripe product/course

    Args:
    - debug (bool)
        - Defaults to False
    """
    try:
        mydb = NormalFunctions.get_mysql_connection(debug=debug)
        cur = mydb.cursor()
        cur.execute("SELECT course_id FROM course")
        courses = cur.fetchall()
    except (pymysql.err.ProgrammingError, pymysql.err.OperationalError):
        print('Database does not yet exist')
        return

    for courseID in courses:
        courseID = courseID[0]

        try:
            stripe.Product.modify(courseID, active = False)
        except InvalidRequestError as error:
            print(error)

def mysql_init_tables(debug:bool=False) -> pymysql.connections.Connection:
    """
    Initialize the database with the necessary tables

    Args:
    - debug (bool): If true, will initialise locally, else will initialise remotely

    Returns:
    - The connection to the database (mysql connection object)
    """
    # Restrict connections to be made from localhost if in debug mode
    # else if not in debug mode, restrict to our custom domain, "coursefinity.social"
    hostName = "localhost" if (debug) else "coursefinity.social" 

    definer = f"root`@`{hostName}"
    mydb = NormalFunctions.get_mysql_connection(debug=debug, database=None)
    cur = mydb.cursor()

    cur.execute("DROP DATABASE IF EXISTS coursefinity")
    mydb.commit()

    cur.execute("CREATE DATABASE coursefinity")
    mydb.commit()
    mydb.close()

    mydb = NormalFunctions.get_mysql_connection(debug=debug)
    cur = mydb.cursor()

    cur.execute("""CREATE TABLE role (
        role_id INTEGER UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        role_name VARCHAR(255) NOT NULL UNIQUE,
        guest_bp BOOL NOT NULL DEFAULT 0,
        general_bp BOOL NOT NULL DEFAULT 0,
        admin_bp BOOL NOT NULL DEFAULT 0,
        logged_in_bp BOOL NOT NULL DEFAULT 0,
        error_bp BOOL NOT NULL DEFAULT 1,
        teacher_bp BOOL NOT NULL DEFAULT 0,
        user_bp BOOL NOT NULL DEFAULT 0
    )""")
    cur.execute("CREATE INDEX role_role_name_idx ON role(role_name)")

    cur.execute("""CREATE TABLE user (
        id VARCHAR(32) PRIMARY KEY, 
        role INTEGER UNSIGNED NOT NULL,
        username VARCHAR(255) NOT NULL UNIQUE, 
        email VARCHAR(255) NOT NULL UNIQUE, 
        email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        password VARBINARY(1024) DEFAULT NULL, -- can be null for user who signed in using Google OAuth2
        profile_image VARCHAR(255) DEFAULT NULL, 
        date_joined DATETIME NOT NULL,
        cart_courses JSON DEFAULT NULL, -- can be null for admin user
        purchased_courses JSON DEFAULT NULL, -- can be null for admin user
        status VARCHAR(255) NOT NULL CHECK (status IN ('Active', 'Inactive', 'Banned')) DEFAULT 'Active',
        FOREIGN KEY (role) REFERENCES role(role_id)
    )""")
    cur.execute("CREATE INDEX user_role_idx ON user(role)")
    cur.execute("CREATE INDEX user_username_idx ON user(username)")
    cur.execute("CREATE INDEX user_email_idx ON user(email)")
    cur.execute("CREATE INDEX user_email_verified_idx ON user(email_verified)")
    cur.execute("CREATE INDEX user_date_joined_idx ON user(date_joined)")
    cur.execute("CREATE INDEX user_status_idx ON user(status)")

    cur.execute("""CREATE TABLE course (
        course_id CHAR(32) PRIMARY KEY, 
        teacher_id VARCHAR(32) NOT NULL,
        course_name VARCHAR(255) NOT NULL,
        course_description VARCHAR(2000) DEFAULT NULL,
        course_image_path VARCHAR(255) DEFAULT NULL,
        course_price DECIMAL(6,2) NOT NULL, -- up to 6 digits, 2 decimal places (max: $9999.99)
        course_category VARCHAR(255) NOT NULL,
        date_created DATETIME NOT NULL,
        video_path VARCHAR(255) NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")
    cur.execute("CREATE INDEX course_course_name_idx ON course(course_name)")
    cur.execute("CREATE INDEX course_course_category_idx ON course(course_category)")
    cur.execute("CREATE INDEX course_date_created_idx ON course(date_created)")

    cur.execute("""CREATE TABLE draft_course (
        course_id CHAR(32) PRIMARY KEY,
        teacher_id VARCHAR(32) NOT NULL,
        video_path VARCHAR(255) NOT NULL,
        date_created DATETIME NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE user_ip_addresses (
        user_id VARCHAR(32) NOT NULL,
        ip_address VARCHAR(32) NOT NULL, -- in hex format, length of 8 for IPv4, length of 32 for IPv6
        last_accessed DATETIME NOT NULL,
        is_ipv4 BOOL NOT NULL DEFAULT TRUE,
        PRIMARY KEY (user_id, ip_address),
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")
    cur.execute("CREATE INDEX ip_address_idx ON user_ip_addresses(ip_address)")
    cur.execute("CREATE INDEX last_accessed_idx ON user_ip_addresses(last_accessed)")
    cur.execute("CREATE INDEX is_ipv4_idx ON user_ip_addresses(is_ipv4)")

    cur.execute("""CREATE TABLE limited_use_jwt (
        id CHAR(64) PRIMARY KEY,
        token_limit TINYINT, -- Min: -128, Max: 127
        expiry_date DATETIME,
        CONSTRAINT check_null CHECK (token_limit IS NOT NULL OR expiry_date IS NOT NULL) -- Both cannot be null
    )""")
    cur.execute("CREATE INDEX limited_use_jwt_token_limit_idx ON limited_use_jwt(token_limit)")
    cur.execute("CREATE INDEX limited_use_jwt_expiry_date_idx ON limited_use_jwt(expiry_date)")

    cur.execute("""CREATE TABLE recovery_token ( 
        user_id VARCHAR(32) PRIMARY KEY, -- will only allow CREATION and DELETION of tokens for this table
        token_id CHAR(64) NOT NULL,
        old_user_email VARCHAR(255) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (token_id) REFERENCES limited_use_jwt(id)
    )""")

    cur.execute("""CREATE TABLE twofa_token (
        user_id VARCHAR(32) PRIMARY KEY,
        token VARBINARY(1024),
        backup_codes_json VARBINARY(1024) DEFAULT NULL, -- Holds at most 8 64 bits hexadecimal (e.g. 'e7b1-4215-89b6-655e') codes that are encrypted as a whole
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")

    cur.execute("""CREATE TABLE login_attempts (
        user_id VARCHAR(32) PRIMARY KEY,
        attempts INTEGER UNSIGNED NOT NULL,
        reset_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")
    cur.execute("CREATE INDEX login_attempts_attempts_idx ON login_attempts(attempts)")
    cur.execute("CREATE INDEX login_attempts_reset_date_idx ON login_attempts(reset_date)")

    cur.execute("""CREATE TABLE session (
        session_id CHAR(64) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        expiry_date DATETIME NOT NULL,
        fingerprint_hash CHAR(128) NOT NULL, -- Will be a SHA512 hash of the user IP address and user agent
        FOREIGN KEY (user_id) REFERENCES user(id)
    )""")
    cur.execute("CREATE INDEX session_expiry_date_idx ON session(expiry_date)")

    cur.execute("""CREATE TABLE review (
        user_id VARCHAR(32),
        course_id CHAR(32),
        course_rating INTEGER UNSIGNED,
        course_review VARCHAR(255),
        review_date DATETIME NOT NULL,
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (course_id) REFERENCES course(course_id)
    )""")
    cur.execute("CREATE INDEX review_course_rating_idx ON review(course_rating)")

    cur.execute("""CREATE TABLE whitelisted_ip_addresses (
        ip_address VARBINARY(512) PRIMARY KEY, -- in encrypted form, for access of admin login portal
        date_added DATETIME NOT NULL
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
        CREATE DEFINER=`{definer}` PROCEDURE `delete_user`(IN user_id_input VARCHAR(32))
        BEGIN
            DELETE FROM course WHERE teacher_id = user_id_input;
            DELETE FROM user_ip_addresses WHERE user_id = user_id_input;
            DELETE FROM twofa_token WHERE user_id = user_id_input;
            DELETE FROM login_attempts WHERE user_id = user_id_input;
            DELETE FROM session WHERE user_id = user_id_input;
            DELETE FROM review WHERE user_id = user_id_input;
            DELETE FROM recovery_token WHERE user_id = user_id_input;
            DELETE FROM user WHERE id = user_id_input;
        END
    """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `delete_recovery_token`(IN user_id_input VARCHAR(32))
        BEGIN
            SET @user_recovery_token := (SELECT token_id FROM recovery_token WHERE user_id=user_id_input);
            DELETE FROM recovery_token WHERE user_id = user_id_input;
            DELETE FROM limited_use_jwt WHERE id = @user_recover_token;
        END
    """)
    """Functions to get Data"""
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
        CREATE DEFINER=`{definer}` PROCEDURE `get_course_data`(IN courseID CHAR(32))
        BEGIN
            SELECT 
            c.course_id, c.teacher_id, 
            u.username, u.profile_image, c.course_name, c.course_description,
            c.course_image_path, c.course_price, c.course_category, c.date_created, 
            ROUND(SUM(r.course_rating) / COUNT(*), 0) AS avg_rating
            FROM course AS c
            LEFT OUTER JOIN review AS r
            ON c.course_id = r.course_id
            INNER JOIN user AS u
            ON c.teacher_id=u.id
            WHERE c.course_id=courseID
            GROUP BY c.course_id;
        END
    """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `get_user_data` (IN user_id VARCHAR(32))
        BEGIN
            SELECT
            u.id, r.role_name, u.username, 
            u.email, u.email_verified, u.password, 
            u.profile_image, u.date_joined, u.cart_courses, 
            u.purchased_courses, u.status, t.token AS has_two_fa
            FROM user AS u
            LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
            INNER JOIN role AS r ON u.role=r.role_id
            WHERE u.id=user_id;
        END
    """)
    
    """Pagination Functions"""
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_teacher_courses`(IN teacherID VARCHAR(32), IN page_number INT)
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM course WHERE teacher_id=teacherID);
            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            teacher_course_info.* FROM (
                SELECT c.course_id, c.teacher_id, 
                u.username, u.profile_image, c.course_name, c.course_description, 
                c.course_image_path, c.course_price, c.course_category, c.date_created,
                ROUND(SUM(r.course_rating) / COUNT(r.user_id), 0) AS avg_rating, @total_course_num
                FROM course AS c
                LEFT OUTER JOIN review AS r ON c.course_id=r.course_id
                INNER JOIN user AS u ON c.teacher_id=u.id
                WHERE c.teacher_id=teacherID
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS teacher_course_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    #For Drafting
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_draft_courses`(IN teacherID VARCHAR(32), IN page_number INT)
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM draft_course WHERE teacher_id=teacherID);
            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            teacher_course_info.* FROM (
                SELECT c.course_id, c.teacher_id, 
                u.username, u.profile_image, c.date_created, @total_course_num
                FROM draft_course AS c
                INNER JOIN user AS u ON c.teacher_id=u.id
                WHERE c.teacher_id=teacherID
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS teacher_course_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `search_course_paginate`(IN page_number INT, IN search_term VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', search_term, '%');
            SET @total_course_num := (SELECT COUNT(*) FROM course WHERE course_name LIKE @search_query);

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            course_info.* FROM (
                SELECT c.course_id, c.teacher_id, 
                u.username, u.profile_image, c.course_name, c.course_description, 
                c.course_image_path, c.course_price, c.course_category, c.date_created, 
                ROUND(SUM(r.course_rating) / COUNT(r.user_id), 0) AS avg_rating, @total_course_num
                FROM course AS c
                LEFT OUTER JOIN review AS r ON c.course_id=r.course_id
                INNER JOIN user AS u ON c.teacher_id=u.id
                WHERE c.course_name LIKE @search_query
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS course_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `explore_course_paginate`(IN page_number INT, IN course_tag VARCHAR(255))
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM course WHERE course_category=course_tag);
            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            course_info.* FROM (
                SELECT c.course_id, c.teacher_id, 
                u.username, u.profile_image, c.course_name, c.course_description, 
                c.course_image_path, c.course_price, c.course_category, c.date_created, 
                ROUND(SUM(r.course_rating) / COUNT(r.user_id), 0) AS avg_rating, @total_course_num
                FROM course AS c
                LEFT OUTER JOIN review AS r ON c.course_id=r.course_id
                INNER JOIN user AS u ON c.teacher_id=u.id
                WHERE c.course_category=course_tag
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS course_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users` (IN page_number INT)
        BEGIN
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE r.role_name<>"Admin" AND r.role_name<>"SuperAdmin);

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE r.role_name<>'Admin'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins` (IN page_number INT)
        BEGIN
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE r.role_name="Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE r.role_name<>'Admin'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users_by_username` (IN page_number INT, IN username_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', username_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE username LIKE @search_query AND r.role_name<>"Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE username LIKE @search_query AND r.role_name<>'Admin'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins_by_username` (IN page_number INT, IN username_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', username_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE username LIKE @search_query AND r.role_name="Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE username LIKE @search_query AND r.role_name<>'Admin'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users_by_uid` (IN page_number INT, IN uid_input VARCHAR(32))
        BEGIN
            SET @search_query := CONCAT('%', uid_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE id LIKE @search_query AND r.role_name<>"Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.id LIKE @search_query AND r.role_name<>'Admin'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins_by_uid` (IN page_number INT, IN uid_input VARCHAR(32))
        BEGIN
            SET @search_query := CONCAT('%', uid_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE id LIKE @search_query AND r.role_name<>"Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.id LIKE @search_query AND r.role_name<>'Admin'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users_by_email` (IN page_number INT, IN email_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', email_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE email LIKE @search_query AND r.role_name<>"Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user 
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.email LIKE @search_query AND r.role_name<>'Admin'
                GROUP BY u.id
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins_by_email` (IN page_number INT, IN email_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', email_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE email LIKE @search_query AND r.role_name="Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, u.cart_courses, 
                u.purchased_courses, u.status, t.token AS has_two_fa, @total_user 
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.email LIKE @search_query AND r.role_name<>'Admin'
                GROUP BY u.id
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset
            ORDER BY row_num
            LIMIT 10;
        END
    """)

    """Datetime function"""
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
    cur.execute("INSERT INTO role (role_name) VALUES ('Student') ")
    cur.execute("INSERT INTO role (role_name) VALUES ('Teacher')")
    cur.execute("INSERT INTO role (role_name) VALUES ('Admin')")
    cur.execute("INSERT INTO role (role_name) VALUES ('SuperAdmin')")
    cur.execute("INSERT INTO role (role_name) VALUES ('Guest')")

    #insert into student role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=0, logged_in_bp=1, error_bp=1, teacher_bp=0, user_bp=0
        WHERE role_id = 1;
    """)

    #insert into Teacher role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=0, logged_in_bp=1, error_bp=1, teacher_bp=1, user_bp=1
        WHERE role_id = 2;
    """)

    #insert into Admin role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=1, logged_in_bp=1, error_bp=1, teacher_bp=0, user_bp=0
        WHERE role_id = 3;
    """)

    #insert into Super Admin role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=0, admin_bp=1, logged_in_bp=1, error_bp=1, teacher_bp=0, user_bp=0
        WHERE role_id = 4;
    """)

    #insert into Guest role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=1, general_bp=1, admin_bp=0, logged_in_bp=0, error_bp=1, teacher_bp=0, user_bp=0
        WHERE role_id = 5;
    """)

    # Insert IP address to whitelist for admin login page
    if (NormalFunctions.CONSTANTS.DEBUG_MODE):
        encryptedLocalhostIP = NormalFunctions.symmetric_encrypt(plaintext="127.0.0.1", keyID=NormalFunctions.CONSTANTS.SENSITIVE_DATA_KEY_ID)
        cur.execute("INSERT INTO whitelisted_ip_addresses (ip_address, date_added) VALUES (%(ip_address)s, SGT_NOW())", {"ip_address": encryptedLocalhostIP})
    else:
        # In production mode, allow access to each member's IP address and NYP's IP address
        ipWhitelist = json.loads(NormalFunctions.CONSTANTS.get_secret_payload(secretID="ip-address-whitelist"))
        encryptedIpList = [NormalFunctions.symmetric_encrypt(plaintext=ip, keyID=NormalFunctions.CONSTANTS.SENSITIVE_DATA_KEY_ID) for ip in ipWhitelist]
        for ip in encryptedIpList:
            cur.execute("INSERT INTO whitelisted_ip_addresses (ip_address, date_added) VALUES (%(ip_address)s, SGT_NOW())", {"ip_address": ip})

    mydb.commit()

    # get users' info for user creation for the database
    passTable = {
        "super-admin": CONSTANTS.get_secret_payload(secretID="sql-super-admin-password"),
        "admin": CONSTANTS.get_secret_payload(secretID="sql-admin-password"),
        "user": CONSTANTS.get_secret_payload(secretID="sql-user-password"),
        "guest": CONSTANTS.get_secret_payload(secretID="sql-guest-password"),
        "teacher": CONSTANTS.get_secret_payload(secretID="sql-teacher-password"),
    }
    superAdminName = f"'super-admin'@'{hostName}'"
    adminName = f"'admin'@'{hostName}'"
    userName = f"'user'@'{hostName}'"
    guestName = f"'guest'@'{hostName}'"
    teacherName=f"'teacher'@'{hostName}'"

    # drop the user if it exists
    cur.execute(f"DROP USER IF EXISTS {superAdminName}")
    cur.execute(f"DROP USER IF EXISTS {adminName}")
    cur.execute(f"DROP USER IF EXISTS {userName}")
    cur.execute(f"DROP USER IF EXISTS {guestName}")
    cur.execute(f"DROP USER IF EXISTS {teacherName}")

    # create the users
    cur.execute(f"CREATE USER {superAdminName} IDENTIFIED BY '{passTable['super-admin']}'")
    cur.execute(f"CREATE USER {adminName} IDENTIFIED BY '{passTable['admin']}'")
    cur.execute(f"CREATE USER {userName} IDENTIFIED BY '{passTable['user']}'")
    cur.execute(f"CREATE USER {guestName} IDENTIFIED BY '{passTable['guest']}'")
    cur.execute(f"CREATE USER {teacherName} IDENTIFIED BY '{passTable['teacher']}'")

    # grant privileges to users
    # More details: https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#privileges-provided-summary
    # TODO: Properly assign roles to each user and to the tables instead of just granting the user the privileges
    # TODO: Read up on https://dev.mysql.com/doc/refman/8.0/en/roles.html

    #TODO: Give proper CRUD to the roles,
    cur.execute("DROP ROLE IF EXISTS 'Admin', 'SuperAdmin', 'Teachers', 'Student', 'Guest';")
    cur.execute(f"CREATE ROLE 'Admin', 'SuperAdmin', 'Teachers', 'Student', 'Guest';")
    cur.execute(f"GRANT EXECUTE, SELECT, INSERT, UPDATE, DELETE ON coursefinity.* TO {superAdminName} WITH GRANT OPTION")
    cur.execute(f"GRANT EXECUTE, SELECT, UPDATE, DELETE ON coursefinity.* TO {adminName} WITH GRANT OPTION")
    cur.execute(f"GRANT EXECUTE, SELECT, INSERT, UPDATE, DELETE ON coursefinity.* TO {userName} WITH GRANT OPTION")
    cur.execute(f"GRANT EXECUTE, SELECT ON coursefinity.* TO {guestName} WITH GRANT OPTION")

    # Grant the privileges
    # Admin Privileges
    cur.execute("GRANT ALL ON coursefinity.role TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.Recovery_token TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.limited_use_jwt TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.user TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.course TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.session TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.twofa_token TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.user_ip_addresses TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.login_attempts TO 'Admin';")
    cur.execute("GRANT ALL ON coursefinity.review TO 'Admin';")

    # SuperAdmin Privileges
    cur.execute("GRANT ALL ON coursefinity.role TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.Recovery_token TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.limited_use_jwt TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.user TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.course TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.session TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.twofa_token TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.user_ip_addresses TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.login_attempts TO 'SuperAdmin';")
    cur.execute("GRANT ALL ON coursefinity.review TO 'SuperAdmin';")

    # Student Privileges 
    cur.execute("GRANT ALL ON coursefinity.role TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.Recovery_token TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.limited_use_jwt TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.user TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.course TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.session TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.twofa_token TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.user_ip_addresses TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.login_attempts TO 'Student';")
    cur.execute("GRANT ALL ON coursefinity.review TO 'Student';")

    # Teacher Privileges
    cur.execute("GRANT ALL ON coursefinity.role TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.Recovery_token TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.limited_use_jwt TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.user TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.course TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.session TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.twofa_token TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.user_ip_addresses TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.login_attempts TO 'Teachers';")
    cur.execute("GRANT ALL ON coursefinity.review TO 'Teachers';")

    # Guest Privileges (probably will be removed, Likely i will have the coursefinity itself to just display)
    cur.execute("GRANT EXECUTE, SELECT ON coursefinity.* TO 'Guest' WITH GRANT OPTION;") # the error is not granting the user the db first
    cur.execute("GRANT ALL ON coursefinity.role TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.Recovery_token TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.limited_use_jwt TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.user TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.course TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.session TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.twofa_token TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.user_ip_addresses TO 'Guest';")
    cur.execute("GRANT ALl ON coursefinity.login_attempts TO 'Guest';")
    cur.execute("GRANT ALL ON coursefinity.review TO 'Guest';")

    # Assign the roles
    cur.execute(f"GRANT 'Admin','SuperAdmin','Teachers','Student','Guest' TO 'root'@'localhost';")
    cur.execute(f"GRANT 'Admin' TO {adminName};")
    cur.execute(f"GRANT 'SuperAdmin' TO {superAdminName};")
    cur.execute(f"GRANT 'Teachers' TO {teacherName};")
    cur.execute(f"GRANT 'Student' TO {userName};")
    cur.execute(f"GRANT 'Guest' TO {guestName};")
    # cur.execute("SET ROLE ALL;") 
    # cur.execute(f"SET PERSIST activate_all_roles_on_login = ON;") # this should be off by default, security misconfig
    # ull also need special privileges for that to enable as well
    # cur.execute("SELECT CURRENT_ROLE()")
    # hi = cur.fetchall()
    # print(hi)

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
        deactivate_stripe_courses(debug=debugFlag)
    except pymysql.err.ProgrammingError:
        pass

    try:
        mysql_init_tables(debug=debugFlag)
        print("Successfully initialised database, \"coursefinity\"!")
    except (pymysql.err.ProgrammingError) as e:
        print("\nProgramming error caught!")
        print("More details:")
        print(e)
    except (Exception) as e:
        print("\nError caught!")
        print("More details:")
        print(e)