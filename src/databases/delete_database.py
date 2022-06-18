import mysql.connector
import os


mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password=os.environ['SQL_PASS']
)

mycursor = mydb.cursor()
mycursor.execute("DROP DATABASE appsecdatabase")