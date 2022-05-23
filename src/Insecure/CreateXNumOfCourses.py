import sqlite3, pathlib, uuid
from datetime import datetime

def generate_id():
    return uuid.uuid4().hex

pyFilePath = pathlib.Path(__file__).parent.absolute().as_posix() + "/databases/database.db"

con = sqlite3.connect(pyFilePath)
cur = con.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id PRIMARY KEY, 
        role TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE, 
        email TEXT NOT NULL UNIQUE, 
        password TEXT NOT NULL, 
        profile_image TEXT, 
        date_joined DATE NOT NULL,
        puchased_courses TEXT NOT NULL
    )""")

res = cur.execute("SELECT * FROM user WHERE id='30a749defdd843ecae5da3b26b6d6b9b'").fetchall()
if (not res):
    # add to the sqlite3 database
    data = ("30a749defdd843ecae5da3b26b6d6b9b", "Teacher", "Daniel", "test@teacher.com", "123123", None, "2022-05-22", "{}")
    cur.execute("INSERT INTO user VALUES (?, ?, ?, ?, ?, ?, ?, ?)", data)
    con.commit()

cur.execute("""CREATE TABLE IF NOT EXISTS course (
        course_id PRIMARY KEY, 
        teacher_id TEXT NOT NULL,
        course_name TEXT NOT NULL,
        course_description TEXT,
        course_image_path TEXT,
        course_price FLOAT NOT NULL,
        course_category TEXT NOT NULL,
        course_total_rating INT NOT NULL,
        course_rating_count INT NOT NULL,
        date_created DATE NOT NULL,
        video_path TEXT NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES user(id)
    )""")

howManyDaniels = int(input("How many courses would you like to create?: "))
for i in range(howManyDaniels):
    course_id = generate_id()
    teacher_id = "30a749defdd843ecae5da3b26b6d6b9b"
    course_name = f"How to be a daniel {i}"
    course_description = f"This course teaches you to learn how to be a daniel part {i}"
    course_image_path = None
    course_price = i * 50.50
    course_category = "Other Academics"
    course_total_rating = 0
    course_rating_count = 0
    date_created = datetime.now().strftime("%Y-%m-%d")

    data = (course_id, teacher_id, course_name, course_description, course_image_path, course_price, course_category, course_total_rating, course_rating_count, date_created)
    cur.execute("INSERT INTO course VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", data)

con.commit()
con.close()

print("Added", i+1, "How to be a daniel courses to the database")