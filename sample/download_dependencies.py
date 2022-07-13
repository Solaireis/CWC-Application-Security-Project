"""
Run this file to download all dependencies with integrity checks.
"""
# import third party libraries
import requests

# import python standard libraries
import hashlib, shutil, platform, sys
from pathlib import Path
from pip._internal import main as pipmain # Old Pip Wrapper, for now it works

#Index of jason file where will return respective file
platformType = platform.system()

# Get system's python version
pyMajorVer = sys.version_info[0]
pyMinorVer = sys.version_info[1]
pyVer = str(pyMajorVer) + str(pyMinorVer) # will get 39, 310, etc.
print(f"Your Python version is: {pyVer}. Your using a {platformType} system.")

headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
}

rootDir = Path(__file__).absolute().parent.parent
dirname = rootDir.joinpath("requirements.txt")
packagedir = rootDir.joinpath("python_packages")
packagedir.mkdir(parents=True, exist_ok=True)

with open(dirname) as f:
    dependencies = [x.strip() for x in f.readlines() if (x.strip() and not x.startswith("#"))]

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

    datafile = (requests.get(f"https://pypi.org/pypi/{name}/json", stream=True, headers=headers, timeout=10)).json()
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

    with requests.get(url, stream=True, headers=headers, timeout=10) as r:
        with open(path, "wb") as f:
            shutil.copyfileobj(r.raw, f)

    with open(path, 'rb') as f:
        data = f.read()
        sha256.update(data)

    if (sha256.hexdigest() != hashed):
        # Path(path).unlink(missing_ok=True)
        print(f"Dependency {lib} does not match the hash!")
    else:
        # Don't uncomment yet, kinda weird, it uninstalled some of my shit because i put latest version
        # It works but its an old way of doing it so need find improved way
        # pipmain(['install', path])
        print(f"Dependency {lib} matches the hash! Successfully Installed & Deleted")
        # Path(path).unlink(missing_ok=True)