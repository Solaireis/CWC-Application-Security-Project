# import python standard libraries
import base64, zlib

# add === for padding to decode flask session
sessionInp = input("Enter session cookie value: ")
print("\nDecoded session cookie value:")
print(zlib.decompress(base64.urlsafe_b64decode(sessionInp.rsplit(".", 2)[0] + "===")))