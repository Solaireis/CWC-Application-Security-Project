import mysql.connector
import os

"""
Run this python file before doing anything

I havent figure out the Remote SQL shit yet so

Set your own SQL Pass for the database as environment variable
Mac Link : https://medium.com/@himanshuagarwal1395/setting-up-environment-variables-in-macos-sierra-f5978369b255
"""

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password=os.environ['SQL_PASS']
)

mycursor = mydb.cursor()
mycursor.execute("CREATE DATABASE appsecdatabase")