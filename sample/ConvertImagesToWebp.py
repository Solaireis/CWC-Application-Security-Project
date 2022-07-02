import pathlib, sys
import re
from importlib.util import spec_from_file_location, module_from_spec
from typing import Union

"""------------------------------ IGNORE CODE BELOW ------------------------------"""

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "python_files", "functions")

# add to sys path so that Constants.py can be imported by NormalFunctions.py
sys.path.append(str(PYTHON_FILES_PATH.parent))

# import NormalFunctions.py local python module using absolute path
NORMAL_PY_FILE = PYTHON_FILES_PATH.joinpath("NormalFunctions.py")
spec = spec_from_file_location("NormalFunctions", str(NORMAL_PY_FILE))
NormalFunctions = module_from_spec(spec)
sys.modules[spec.name] = NormalFunctions
spec.loader.exec_module(NormalFunctions)

"""------------------------------ IGNORE CODE ABOVE ------------------------------"""

"""------------------------------ MAIN CODE BELOW ------------------------------"""

ALLOWED_IMAGE_EXTENSIONS = ("png", "jpeg", "jpg")

def get_input() -> Union[str, list]:
    """
    Get input from user
    """
    while (1):
        print(
            "Demo image should be at the root of the workspace,", 
            "i.e. the root folder that contains the res, sample, src, test, folders!",
            "Note: For multiple images at once, separate them by a comma.",
            sep="\n", end="\n\n"
        )
        IMAGE_NAME = input("Enter demo image name (with extension suffix, X to shutdown): ").strip()
        if (IMAGE_NAME.lower() == "x"):
            return IMAGE_NAME
        elif (IMAGE_NAME == ""):
            print("Error: Image name cannot be empty!\n")
            continue
        elif ("," in IMAGE_NAME):
            imageList = [img.strip() for img in IMAGE_NAME.split(",")]
            invalid = False
            for img in imageList:
                if (img == ""):
                    print("Error: All image names cannot be empty!\n")
                    invalid = True
                    break
                elif (img.rsplit(".", 1)[-1] not in ALLOWED_IMAGE_EXTENSIONS):
                    print("Error: All image names must end with .png!\n")
                    invalid = True
                    break
            if (invalid):
                continue
            return imageList
        elif (IMAGE_NAME.rsplit(".", 1)[-1] not in ALLOWED_IMAGE_EXTENSIONS):
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
        imagesToConvertArr = []
        if (isinstance(IMAGE_NAME, str)):
            imagesToConvertArr.append(
                pathlib.Path(__file__).parent.parent.absolute().joinpath(IMAGE_NAME)
            )
        elif (isinstance(IMAGE_NAME, list)):
            for img in IMAGE_NAME:
                imagesToConvertArr.append(
                    pathlib.Path(__file__).parent.parent.absolute().joinpath(img)
                )

        # Open image and convert it to webp
        errorMsgArr = []
        for imgPath in imagesToConvertArr:
            try:
                NormalFunctions.compress_and_resize_image(
                    imgPath, 
                    imgPath.with_suffix(".webp"), 
                    dimensions=(1920, 1080)
                )
            except (FileNotFoundError):
                errorMsgArr.append(imgPath.name)

        # Print error message if any
        if (len(errorMsgArr) > 0):
            print("Error:\tThe following image(s) were not found:")
            print("\t", ", ".join(errorMsgArr), "...", sep="")
        else:
            print("Success: All image(s) were converted to webp successfully!")
        print()

"""------------------------------ MAIN CODE ABOVE ------------------------------"""

if (__name__ == "__main__"):
    main()
    sys.exit(0)