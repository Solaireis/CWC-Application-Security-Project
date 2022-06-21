# import python standard libraries
from secrets import token_bytes
import pathlib

FILE_PATH = pathlib.Path(__file__).parent.absolute()
SECRET_KEY_PATH = FILE_PATH.joinpath("flask-secret-key.bin")

numOfBytes = 512
secretKey = token_bytes(numOfBytes)
print("Generated secret key:", secretKey, end="\n\n", sep="\n")

with open(SECRET_KEY_PATH, "wb") as f: 
    f.write(secretKey)
print("Saved secret key to", SECRET_KEY_PATH, sep="\n", end="\n\n")

print("Reading secret key from the saved file...")
with open(SECRET_KEY_PATH, "rb") as f: 
    readSecretKey = f.read()

print("Verdict: ", end="")
if (secretKey == readSecretKey):
    print("Saved key matches the generated key!")
else:
    print("Saved key does not match with the generated key in Python!")