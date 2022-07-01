import pathlib, sys
from importlib.util import spec_from_file_location, module_from_spec

"""------------------------------ IGNORE CODE BELOW ------------------------------"""

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "python_files")

# add to sys path so that Constants.py can be imported by NormalFunctions.py
sys.path.append(str(PYTHON_FILES_PATH))

# import NormalFunctions.py local python module using absolute path
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("NormalFunctions.py")
spec = spec_from_file_location("NormalFunctions", str(NORMAL_PY_FILE))
NormalFunctions = module_from_spec(spec)
sys.modules[spec.name] = NormalFunctions
spec.loader.exec_module(NormalFunctions)

"""------------------------------ IGNORE CODE ABOVE ------------------------------"""

"""------------------------------ MAIN CODE BELOW ------------------------------"""

def get_input() -> str:
    """
    Get input from user
    """
    while (1):
        print(
            "Demo image should be at the root of the workspace,", 
            "i.e. the root folder that contains the res, sample, src, test, folders!",
            sep="\n"
        )
        IMAGE_NAME = input("Enter demo image name (with extension suffix, X to shutdown): ").strip()
        if (IMAGE_NAME.lower() == "x"):
            return IMAGE_NAME
        elif (IMAGE_NAME == ""):
            print("Error: Image name cannot be empty!\n")
            continue
        elif (IMAGE_NAME.rsplit(".", 1)[-1] not in ("png", "jpeg", "jpg")):
            print("Error: Image extension must be png, jpeg or jpg!\n")
            continue
        else:
            return IMAGE_NAME

def main() -> None:
    while (1):
        IMAGE_NAME = get_input()
        if (IMAGE_NAME == "x"):
            print("\nExiting...")
            input("Press Enter to exit...")
            return

        # Demo image should be at the root of the workspace, i.e. the root folder
        # that contains the res, sample, src, test, folders!
        IMAGE_PATH = pathlib.Path(__file__).parent.parent.absolute().joinpath(IMAGE_NAME)

        # Open image and convert it to webp
        try:
            NormalFunctions.compress_and_resize_image(
                IMAGE_PATH, 
                IMAGE_PATH.with_suffix(".webp"), 
                dimensions=(1920, 1080)
            )
            print("Alert: Successfully converted image to webp!")
        except (FileNotFoundError):
            print("Alert: Image not found!")
        print()

"""------------------------------ MAIN CODE ABOVE ------------------------------"""

if (__name__ == "__main__"):
    main()
    sys.exit(0)