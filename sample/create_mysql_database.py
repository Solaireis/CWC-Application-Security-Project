"""
For development purposes, to be removed from any imports during production environment.
"""
# import third party libraries
import pymysql
import stripe
from stripe.error import InvalidRequestError

# import python standard libraries
import pathlib, sys
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
SECRET_CONSTANTS = NormalFunctions.SECRET_CONSTANTS
stripe.api_key = SECRET_CONSTANTS.STRIPE_SECRET_KEY

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
        print("Database does not yet exist")
        return

    for courseID in courses:
        try:
            stripe.Product.modify(courseID[0], active = False)
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
    hostName = "localhost" if (debug) else "%"

    definer = f"coursefinity`@`{hostName}"
    mydb = NormalFunctions.get_mysql_connection(debug=debug, database=None, user="root")
    cur = mydb.cursor()

    cur.execute("DROP DATABASE IF EXISTS coursefinity")
    mydb.commit()

    cur.execute("CREATE DATABASE coursefinity")
    mydb.commit()
    mydb.close()

    mydb = NormalFunctions.get_mysql_connection(debug=debug, user="root")
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
        user_bp BOOL NOT NULL DEFAULT 0,
        super_admin_bp BOOL NOT NULL DEFAULT 0
    )""")
    cur.execute("CREATE INDEX role_role_name_idx ON role(role_name)")

    cur.execute("""CREATE TABLE user (
        id VARCHAR(32) PRIMARY KEY, 
        role INTEGER UNSIGNED NOT NULL,
        username VARCHAR(255) NOT NULL UNIQUE, 
        email VARCHAR(255), 
        email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        password VARBINARY(1024) DEFAULT NULL, -- can be null for user who signed in using Google OAuth2
        profile_image VARCHAR(255) DEFAULT NULL, 
        date_joined DATETIME NOT NULL,
        status VARCHAR(255) NOT NULL CHECK (status IN ('Active', 'Inactive', 'Banned', 'Deleted')) DEFAULT 'Active',
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
        active BOOL NOT NULL DEFAULT TRUE,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")
    cur.execute("CREATE INDEX course_course_name_idx ON course(course_name)")
    cur.execute("CREATE INDEX course_course_category_idx ON course(course_category)")
    cur.execute("CREATE INDEX course_date_created_idx ON course(date_created)")
    cur.execute("CREATE INDEX course_teacher_idx ON course(teacher_id)")
    cur.execute("CREATE INDEX course_active_idx ON course(active)")

    cur.execute("""CREATE TABLE cart(
        user_id VARCHAR(32) NOT NULL,
        course_id CHAR(32) NOT NULL,
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (course_id) REFERENCES course(course_id) 
    )""")

    cur.execute("""CREATE TABLE purchased_courses(
        user_id VARCHAR(32) NOT NULL,
        course_id CHAR(32) NOT NULL,
        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (course_id) REFERENCES course(course_id)
    )""")

    cur.execute("""CREATE TABLE draft_course (
        course_id CHAR(32) PRIMARY KEY,
        teacher_id VARCHAR(32) NOT NULL,
        video_path VARCHAR(255) NOT NULL,
        date_created DATETIME NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id) ON DELETE CASCADE
    )""")
    cur.execute("CREATE INDEX draft_course_teacher_idx ON draft_course(teacher_id)")
    cur.execute("CREATE INDEX draft_course_date_created_idx ON draft_course(date_created)")

    cur.execute("""CREATE TABLE stripe_payments (
        payment_id VARCHAR(32) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        cart_courses JSON NOT NULL,
        stripe_payment_intent VARCHAR(32), -- actual length 27, but may change in the future; generate_id() has 32
        created_time DATETIME NOT NULL,
        payment_time DATETIME,
        amount DECIMAL(6,2) NOT NULL, -- up to 6 digits, 2 decimal places (max: $9999.99)
        receipt_email VARCHAR(255),
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )""")
    cur.execute("CREATE INDEX stripe_payments_user_idx ON stripe_payments(user_id)")

    cur.execute("""CREATE TABLE user_ip_addresses (
        user_id VARCHAR(32) NOT NULL,
        ip_address VARCHAR(32) NOT NULL, -- in hex format, length of 8 for IPv4, length of 32 for IPv6
        last_accessed DATETIME NOT NULL,
        is_ipv4 BOOL NOT NULL DEFAULT TRUE,
        PRIMARY KEY (user_id, ip_address),
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )""")
    cur.execute("CREATE INDEX user_ip_addresses_ip_address_idx ON user_ip_addresses(ip_address)")
    cur.execute("CREATE INDEX user_ip_addresses_last_accessed_idx ON user_ip_addresses(last_accessed)")
    cur.execute("CREATE INDEX user_ip_addresses_is_ipv4_idx ON user_ip_addresses(is_ipv4)")
    cur.execute("CREATE INDEX user_ip_addresses_user_id_idx ON user_ip_addresses(user_id)")

    cur.execute("""CREATE TABLE expirable_token (
        token CHAR(240) PRIMARY KEY, -- base85 encoded token since a hexadecimal token would be too long for a PK
        user_id VARCHAR(32) NOT NULL,
        expiry_date DATETIME,
        purpose VARCHAR(30) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )""")
    cur.execute("CREATE INDEX expirable_token_user_idx ON expirable_token(user_id)")
    cur.execute("CREATE INDEX expirable_token_expiry_date_idx ON expirable_token(expiry_date)")

    cur.execute("""CREATE TABLE limited_use_jwt (
        id CHAR(64) PRIMARY KEY,
        token_limit TINYINT, -- Min: -128, Max: 127
        expiry_date DATETIME,
        CONSTRAINT check_null CHECK (token_limit IS NOT NULL OR expiry_date IS NOT NULL) -- Both cannot be null
    )""")
    cur.execute("CREATE INDEX limited_use_jwt_token_limit_idx ON limited_use_jwt(token_limit)")
    cur.execute("CREATE INDEX limited_use_jwt_expiry_date_idx ON limited_use_jwt(expiry_date)")

    cur.execute("""CREATE TABLE acc_recovery_token ( 
        user_id VARCHAR(32) PRIMARY KEY, -- will only allow CREATION and DELETION of tokens for this table
        token CHAR(240) NOT NULL,
        old_user_email VARCHAR(255) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (token) REFERENCES expirable_token(token) ON DELETE CASCADE
    )""")

    cur.execute("""CREATE TABLE twofa_token (
        user_id VARCHAR(32) PRIMARY KEY,
        token VARBINARY(1024),
        backup_codes_json VARBINARY(1024) DEFAULT NULL, -- Holds at most 8 64 bits hexadecimal (e.g. 'e7b1-4215-89b6-655e') codes that are encrypted as a whole
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )""")

    cur.execute("""CREATE TABLE login_attempts (
        user_id VARCHAR(32) PRIMARY KEY,
        attempts INTEGER UNSIGNED NOT NULL,
        reset_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )""")
    cur.execute("CREATE INDEX login_attempts_attempts_idx ON login_attempts(attempts)")
    cur.execute("CREATE INDEX login_attempts_reset_date_idx ON login_attempts(reset_date)")

    cur.execute("""CREATE TABLE session (
        session_id CHAR(64) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL,
        expiry_date DATETIME NOT NULL,
        fingerprint_hash CHAR(128) NOT NULL, -- Will be a SHA512 hash of the user IP address and user agent
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
    )""")
    cur.execute("CREATE INDEX session_user_id_idx ON session(user_id)")
    cur.execute("CREATE INDEX session_expiry_date_idx ON session(expiry_date)")
    cur.execute("CREATE INDEX session_fingerprint_hash_idx ON session(fingerprint_hash)")

    cur.execute("""CREATE TABLE review (
        user_id VARCHAR(32),
        course_id CHAR(32),
        course_rating INTEGER UNSIGNED,
        course_review VARCHAR(255),
        review_date DATETIME NOT NULL,

        PRIMARY KEY (user_id, course_id),
        FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (course_id) REFERENCES course(course_id) 
    )""")
    cur.execute("CREATE INDEX review_user_id_idx ON review(user_id)")
    cur.execute("CREATE INDEX review_course_id_idx ON review(course_id)")
    cur.execute("CREATE INDEX review_course_rating_idx ON review(course_rating)")
    cur.execute("CREATE INDEX review_review_date_idx ON review(review_date)")

    # end of table creation
    mydb.commit()

    # Stored Procedures
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `delete_user_data`(IN user_id_input VARCHAR(32))
        BEGIN
            UPDATE course SET active=0 WHERE teacher_id=user_id_input;

            UPDATE user SET email=NULL, password=NULL, profile_image=NULL, status='Deleted', 
            role=(SELECT role_id FROM role WHERE role_name='Student'),
            username=CONCAT('deleted-user-', UUID_V4()) -- totally not copying discord (;
            WHERE id=user_id_input;

            DELETE FROM purchased_courses WHERE user_id=user_id_input;
            DELETE FROM draft_course WHERE teacher_id = user_id_input;
            DELETE FROM review WHERE user_id = user_id_input;
            DELETE FROM review WHERE course_id IN (SELECT course_id FROM course WHERE teacher_id = user_id_input);
            DELETE FROM user_ip_addresses WHERE user_id = user_id_input;
            DELETE FROM twofa_token WHERE user_id = user_id_input;
            DELETE FROM login_attempts WHERE user_id = user_id_input;
            DELETE FROM session WHERE user_id = user_id_input;
            DELETE FROM acc_recovery_token WHERE user_id = user_id_input;
            DELETE FROM expirable_token WHERE user_id = user_id_input;
        END
    """)
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `delete_acc_recovery_token`(IN user_id_input VARCHAR(32))
        BEGIN
            DELETE FROM acc_recovery_token WHERE user_id = user_id_input;
            DELETE FROM expirable_token WHERE id = user_id_input;
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
            ROUND(SUM(r.course_rating) / COUNT(*), 0) AS avg_rating, c.video_path, c.active
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
        CREATE DEFINER=`{definer}` PROCEDURE `get_user_data` (IN user_id_input VARCHAR(32), IN get_cart_data BOOLEAN)
        BEGIN
            SELECT
            u.id, r.role_name, u.username, 
            u.email, u.email_verified, u.password, 
            u.profile_image, u.date_joined, 
            IF(get_cart_data, (SELECT JSON_ARRAYAGG(course_id) FROM cart WHERE user_id=user_id_input), NULL) AS cart_courses,
            u.status, t.token AS has_two_fa
            FROM user AS u
            LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
            INNER JOIN role AS r ON u.role=r.role_id
            WHERE u.id=user_id_input;
        END
    """)

    # Pagination Functions
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_purchased_courses` (IN user_id_input VARCHAR(32), IN page_number INT)
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM purchased_courses WHERE user_id=user_id);

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
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
                INNER JOIN purchased_courses AS pc ON pc.course_id=c.course_id
                WHERE pc.user_id=user_id_input
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS course_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_teacher_courses`(IN teacherID VARCHAR(32), IN page_number INT)
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM course WHERE teacher_id=teacherID);

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
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
                WHERE c.teacher_id=teacherID AND c.active=1
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS teacher_course_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    # For Drafting
    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_draft_courses`(IN teacherID VARCHAR(32), IN page_number INT)
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM draft_course WHERE teacher_id=teacherID);
            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            teacher_course_info.* FROM (
                SELECT c.course_id, c.teacher_id, 
                u.username, u.profile_image, c.date_created, c.video_path, @total_course_num
                FROM draft_course AS c
                INNER JOIN user AS u ON c.teacher_id=u.id
                WHERE c.teacher_id=teacherID
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS teacher_course_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `search_course_paginate`(IN page_number INT, IN search_term VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', search_term, '%');
            SET @total_course_num := (SELECT COUNT(*) FROM course WHERE course_name LIKE @search_query);

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
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
                WHERE c.course_name LIKE @search_query AND c.active=1
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS course_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `explore_course_paginate`(IN page_number INT, IN course_tag VARCHAR(255))
        BEGIN
            SET @total_course_num := (SELECT COUNT(*) FROM course WHERE course_category=course_tag);
            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
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
                WHERE c.course_category=course_tag AND c.active=1
                GROUP BY c.course_id
                ORDER BY c.date_created DESC -- show most recent courses first
            ) AS course_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users` (IN page_number INT)
        BEGIN
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE r.role_name IN ('Student', 'Teacher'));

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE r.role_name IN ('Student', 'Teacher') AND u.status <> 'Deleted'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins` (IN page_number INT)
        BEGIN
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE r.role_name='Admin');

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE r.role_name = 'Admin' AND u.status <> 'Deleted'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users_by_username` (IN page_number INT, IN username_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', username_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE username LIKE @search_query 
                                AND r.role_name IN ('Student', 'Teacher'));

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE username LIKE @search_query AND r.role_name IN ('Student', 'Teacher') AND u.status <> 'Deleted'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins_by_username` (IN page_number INT, IN username_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', username_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE username LIKE @search_query AND r.role_name='Admin');

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart, u.status, 
                t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE username LIKE @search_query AND r.role_name='Admin' AND u.status <> 'Deleted'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users_by_uid` (IN page_number INT, IN uid_input VARCHAR(32))
        BEGIN
            SET @search_query := CONCAT('%', uid_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE id LIKE @search_query
                                AND r.role_name IN ('Student', 'Teacher'));

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.id LIKE @search_query AND r.role_name IN ('Student', 'Teacher') AND u.status <> 'Deleted'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_admins_by_uid` (IN page_number INT, IN uid_input VARCHAR(32))
        BEGIN
            SET @search_query := CONCAT('%', uid_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE id LIKE @search_query AND r.role_name="Admin");

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num,
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.id LIKE @search_query AND r.role_name='Admin' AND u.status <> 'Deleted'
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_users_by_email` (IN page_number INT, IN email_input VARCHAR(255))
        BEGIN
            SET @search_query := CONCAT('%', email_input, '%');
            SET @total_user := (SELECT COUNT(*) FROM user AS u
                                INNER JOIN role AS r ON u.role=r.role_id
                                WHERE email LIKE @search_query
                                AND r.role_name IN ('Student', 'Teacher'));

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user 
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.email LIKE @search_query AND r.role_name IN ('Student', 'Teacher') AND u.status <> 'Deleted'
                GROUP BY u.id
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
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
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            user_info.* FROM (
                SELECT u.id, r.role_name, u.username, 
                u.email, u.email_verified, u.password, 
                u.profile_image, u.date_joined, NULL as cart,
                u.status, t.token AS has_two_fa, @total_user 
                FROM user AS u
                LEFT OUTER JOIN twofa_token AS t ON u.id=t.user_id
                INNER JOIN role AS r ON u.role=r.role_id
                WHERE u.email LIKE @search_query AND r.role_name='Admin' AND u.status <> 'Deleted'
                GROUP BY u.id
                ORDER BY u.date_joined DESC -- show newest users first
            ) AS user_info
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    cur.execute(f"""
        CREATE DEFINER=`{definer}` PROCEDURE `paginate_review_by_course` (IN page_number INT, IN course_id_input CHAR(32))
        BEGIN
            SET @total_reviews := (SELECT COUNT(*) FROM review WHERE course_id=course_id_input GROUP BY course_id);

            SET @page_offset := (page_number - 1) * 10;
            SET @page_limit := @page_offset + 10;
            SET @count := 0;
            SELECT (@count := @count + 1) AS row_num, 
            review.* FROM (
                SELECT 
                r.user_id, r.course_id, r.course_rating, 
                r.course_review, r.review_date, u.username, @total_reviews 
                FROM review r 
                INNER JOIN user u ON r.user_id=u.id 
                WHERE r.course_id=course_id_input
                ORDER BY r.review_date DESC -- show newest reviews first
            ) AS review
            HAVING row_num > @page_offset AND row_num <= @page_limit
            ORDER BY row_num;
        END
    """)

    # Datetime function
    cur.execute(f"""
        CREATE DEFINER=`{definer}` FUNCTION SGT_NOW() 
            RETURNS DATETIME 
        DETERMINISTIC 
        COMMENT 'Returns SGT (UTC+8) datetime.'
        BEGIN
            RETURN CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+08:00');
        END
    """)

    # UUID_V4 function based on https://stackoverflow.com/a/61062917/16377492
    cur.execute(f"""
        CREATE DEFINER=`{definer}` FUNCTION UUID_V4()
            RETURNS CHAR(36)
        DETERMINISTIC
        COMMENT 'Returns a random UUID v4 (36 or 32 Characters string).'
        BEGIN
            -- 1th and 2nd block are made of 6 random bytes
            SET @h1 = HEX(RANDOM_BYTES(4));
            SET @h2 = HEX(RANDOM_BYTES(2));

            -- 3th block will start with a 4 indicating the version, remaining is random
            SET @h3 = CONCAT('4', SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3));

            -- 4th block first nibble can only be 8, 9 A or B, remaining is random
            SET @h4 = CONCAT(
                HEX(FLOOR(ASCII(RANDOM_BYTES(1)) / 64) + 8),
                SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3)
            );

            -- 5th block is made of 6 random bytes
            SET @h5 = HEX(RANDOM_BYTES(6));

            -- Build the complete UUID
            RETURN LOWER(CONCAT_WS(
                '-', @h1, @h2, @h3, @h4, @h5
            ));
        END
    """)

    # end of stored procedures and functions
    mydb.commit()

    # data initialisation
    cur.execute("INSERT INTO role (role_name) VALUES ('Student') ")
    cur.execute("INSERT INTO role (role_name) VALUES ('Teacher')")
    cur.execute("INSERT INTO role (role_name) VALUES ('Admin')")
    cur.execute("INSERT INTO role (role_name) VALUES ('SuperAdmin')")
    cur.execute("INSERT INTO role (role_name) VALUES ('Guest')")

    # insert into student role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=0, logged_in_bp=1, error_bp=1, teacher_bp=0, user_bp=1 , super_admin_bp=0
        WHERE role_id = 1;
    """)

    # insert into Teacher role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=0, logged_in_bp=1, error_bp=1, teacher_bp=1, user_bp=1 , super_admin_bp=0
        WHERE role_id = 2;
    """)

    # insert into Admin role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=1, logged_in_bp=1, error_bp=1, teacher_bp=0, user_bp=0 , super_admin_bp=0
        WHERE role_id = 3;
    """)

    # insert into Super Admin role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=0, general_bp=1, admin_bp=1, logged_in_bp=1, error_bp=1, teacher_bp=0, user_bp=0 , super_admin_bp=1
        WHERE role_id = 4;
    """)

    # insert into Guest role the rbac
    cur.execute("""
        UPDATE role SET 
        guest_bp=1, general_bp=1, admin_bp=0, logged_in_bp=0, error_bp=1, teacher_bp=0, user_bp=0 , super_admin_bp=0
        WHERE role_id = 5;
    """)
    mydb.commit()

    # get users' info for user creation for the database
    coursefinityName = f"'coursefinity'@'{hostName}'"

    # drop the user if it exists
    cur.execute(f"DROP USER IF EXISTS {coursefinityName}")

    # create the users
    coursefinitySQLPass = SECRET_CONSTANTS.get_secret_payload(secretID="sql-coursefinity-password")
    cur.execute(f"CREATE USER {coursefinityName} IDENTIFIED BY '{coursefinitySQLPass}'")

    # grant the coursefinity web app MySQL account 
    # privileges for CRUD of tuples and Execute (for calling stored procedures)
    cur.execute(f"GRANT EXECUTE, SELECT, INSERT, UPDATE, DELETE ON coursefinity.* TO {coursefinityName} WITH GRANT OPTION")

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