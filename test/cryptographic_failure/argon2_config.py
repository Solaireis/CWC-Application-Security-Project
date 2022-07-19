# import python standard libraries
from sys import modules
import pathlib
from importlib.util import spec_from_file_location, module_from_spec
from timeit import repeat

# import third party libraries
from argon2 import PasswordHasher

# import Constants.py local python module using absolute path
FILE_PATH = pathlib.Path(__file__).parent.absolute()
CONSTANTS_PY_FILE = FILE_PATH.parent.parent.joinpath("src", "python_files", "classes","Constants.py")
spec = spec_from_file_location("Constants", str(CONSTANTS_PY_FILE))
Constants = module_from_spec(spec)
modules[spec.name] = Constants
spec.loader.exec_module(Constants)

DEFAULT_PH = PasswordHasher()
CONFIGURED_PH = Constants.CONSTANTS.PH
REPEAT_NUM = 5

passwordInput = input("Enter password to hash: ")

print("\nAverage time taken for hashing the password,\n\"", passwordInput, f"\", {REPEAT_NUM} times...", sep="", end="\n\n")

print("Default:", sum(repeat(
    stmt=f"DEFAULT_PH.hash('{passwordInput}')", 
    setup="from __main__ import DEFAULT_PH",
    repeat=REPEAT_NUM,
    number=1)) / REPEAT_NUM,
    sep="\t\t"
)
print("Manually configured:", sum(repeat(
    stmt=f"CONFIGURED_PH.hash('{passwordInput}')", 
    setup="from __main__ import CONFIGURED_PH",
    repeat=REPEAT_NUM,
    number=1)) / REPEAT_NUM,
    sep="\t"
)