import shelve, uuid, pathlib
from python_files.Student import Student

def generate_ID(inputDict):
    generatedID = str(uuid.uuid4())
    if generatedID in inputDict:
        generate_ID(inputDict) # using recursion if there is a collision to generate a new unique ID
    return generatedID

userDict = {}
db = shelve.open(str(pathlib.Path.cwd()) + "\\databases" + "\\user", "c")
try:
    if 'Users' in db:
        userDict = db['Users']
    else:
        print("No user data in user shelve files.")
        db["Users"] = userDict
except:
    db.close()
    print("Error in retrieving Users from user.db")

noOfUser = int(input("How many user account to create?: "))
    
getLatestTestI = len(userDict)
# print(getLatestTestI)
for i in range(getLatestTestI, noOfUser+getLatestTestI):
    email = "test" + str(i) + "@gmail.com"
    username = "test" + str(i)
    uid = generate_ID(userDict)
    user = Student(uid, username, email, "123123")
    userDict[uid] = user
    print(f"User {username}, created with the ID, {uid}.")

db["Users"] = userDict
db.close()
print(f"{noOfUser} users created successfully.")