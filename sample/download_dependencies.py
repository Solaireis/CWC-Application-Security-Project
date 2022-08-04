"""
Run this file to download all dependencies with integrity checks.
"""
# import python standard libraries
import hashlib, shutil, json, platform, sys, os
from urllib.request import Request, urlopen
from pathlib import Path

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
}

def download_file(url:str, file:Path, length:int=1024*1024) -> None:
    """
    Downloads a file from a url and saves it to a file.

    Args:
    - url (str): url of the file to download
    - file (pathlib.Path): the file path to save to
    - length (int): the length of each chunk of the file to download (in bits)
        - Default: 1 MiB per chunk
    """
    req = urlopen(Request(url, headers=HEADERS), timeout=10)
    with open(file, "wb") as fp:
        shutil.copyfileobj(req, fp, length)

def main() -> None:
    # Index of json file where will return respective file
    platformType = platform.system()
    PIP_OS_COMMAND = "python3 -m pip install" if (platformType != "Windows") else "pip install"

    # Get system's python version
    pyMajorVer = sys.version_info[0]
    pyMinorVer = sys.version_info[1]
    pyVer = str(pyMajorVer) + str(pyMinorVer) # will get 39, 310, etc.
    print(f"Your Python version is: {pyVer}. Your using a {platformType} system.")

    # initialising variables
    rootDir = Path(__file__).absolute().parent.parent
    dirname = rootDir.joinpath("requirements.txt")
    packagedir = rootDir.joinpath("python_packages")
    packagedir.mkdir(parents=True, exist_ok=True)

    dependencies = ["gunicorn>=20.1.0"] # add green unicorn, aka gunicorn, for hosting the web app
    with open(dirname) as f:
        for dependency in f:
            dependency = dependency.strip()
            if (dependency and not dependency.startswith("#")):
                dependencies.append(dependency)

    for lib in dependencies:
        maximum = False
        sha256 = hashlib.sha256()

        name = lib.split(">")[0]
        version = (lib.split("=")[-1]).strip()
        try:
            version = (version.split(",")[1]).strip()
            maximum = True
        except:
            pass

        datafile = json.load(urlopen(Request(f"https://pypi.org/pypi/{name}/json", headers=HEADERS), timeout=10))
        file = datafile["releases"]
        versions = list(file)

        for j in range(len(versions)-1, -1, -1):
            if (not maximum):
                if (versions[j] >= version):
                    version = versions[j]
                    break
            else:
                if (versions[j] < version):
                    version = versions[j]
                    break

        try:
            file = datafile["releases"][version][2]
            for i in datafile["releases"][version]:
                url = i["url"]
                file = i
                if(f"cp{pyVer}" in url) or (f"pp{pyVer}" in url):
                    if (platformType == "Darwin"):
                        if ("macosx" in url):
                            break
                    elif (platformType == "Linux"):
                        if ("linux" in url) and ("64" in url):
                            break
                    else:
                        # for Windows 64-bit machines
                        if ("amd" in url and "64" in url):
                            break
        except:
            file = datafile["releases"][version][0]
            url = file["url"]

        filename = file["filename"]
        hashed = file["digests"]["sha256"]
        path = f"{packagedir}/{filename}"
        download_file(url, path)

        with open(path, "rb") as f:
            data = f.read()
            sha256.update(data)

        if (sha256.hexdigest() != hashed):
            Path(path).unlink(missing_ok=True)
            print(f"Dependency {lib} does not match the hash!")
            return 1
        else:
            os.system(f"{PIP_OS_COMMAND} {lib}")
            print(f"Dependency {lib} matches the hash! Successfully Installed & Deleted")
            Path(path).unlink(missing_ok=True)

    return 0

if (__name__ == "__main__"):
    returnCode = main()
    print(f"Exiting with code: {returnCode}")
    sys.exit(returnCode)