import sqlite3, pathlib, uuid
from datetime import datetime
from random import randint
from python_files.NormalFunctions import generate_id

pyFilePath = pathlib.Path(__file__).parent.absolute().joinpath("databases", "database.db")

con = sqlite3.connect(pyFilePath)
cur = con.cursor()
cur.execute("""CREATE TABLE IF NOT EXISTS review (
        user_id TEXT,
        course_id TEXT,
        course_rating INTEGER,
        course_review TEXT,
        
        PRIMARY KEY (user_id, course_id)
    )""")

