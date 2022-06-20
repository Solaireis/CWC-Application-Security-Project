import sqlite3, pathlib, uuid

import mysql.connector
from os import environ
from datetime import datetime
from random import randint
from python_files.NormalFunctions import generate_id

while (1):
    debugPrompt = input("Debug mode? (Y/n): ").lower().strip()
    if (debugPrompt not in ("y", "n", "")):
        print("Invalid input", end="\n\n")
        continue
    else:
        debugFlag = True if (debugPrompt != "n") else False
        break

if (debugFlag):
    host = "localhost"
    password = environ["LOCAL_SQL_PASS"]
else:
    host = "34.143.163.29" # Google Cloud SQL Public address
    password = environ["REMOTE_SQL_PASS"]

try:
    con = mysql.connector.connect(
        host=host,
        user="root",
        password=password,
        database="coursefinity",
    )
except (mysql.connector.errors.ProgrammingError):
    print("Database Not Found. Please create one first")
cur = con.cursor(buffered=True)

cur.execute("""CREATE TABLE IF NOT EXISTS admin (
        id CHAR(32) PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE, 
        email VARCHAR(255) NOT NULL UNIQUE, 
        password VARCHAR(255) NOT NULL,
        account_creation_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")

admAcc = int(input("How many admins would you like to create? Min:1 Max:100: "))
while (admAcc < 0 or admAcc > 100):
    print("Enter the number of admins to create between 1 to 100")
    admAcc = int(input("How many admins would you like to create? Min:1 Max:100: "))

cur.execute("SELECT * FROM admin")
res = cur.fetchall()
if (len(res) < admAcc):
    for i in range(admAcc - len(res)):
        id = generate_id()
        username = input("Enter the username of the admin: ")
        email = input("Enter the email of the admin: ")
        password = input("Enter the password of the admin: ")
        data = (id, username, email, password, datetime.now())
        cur.execute("INSERT INTO admin VALUES (%s, %s, %s, %s, %s)", data)
        con.commit()

con.commit()
con.close()
print("Done")