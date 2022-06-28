# import third party libraries
import requests

# import python standard libraries
import hashlib
from pathlib import Path
import shutil
import platform
from pip._internal import main as pipmain # Old Pip Wrapper, for now it works

#Index of jason file where will return respective file
platforms = {"Darwin": 0, "Linux": 1, "Windows": 2}
platformType = platform.system()

headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
}

dirname = Path(__file__).absolute().parent.parent.parent.joinpath("requirements.txt")
packagedir = Path(__file__).absolute().parent.parent.joinpath("python_packages")
packagedir.mkdir(parents=True, exist_ok=True)

with open(dirname) as f:
    dependencies = f.readlines()


for i in dependencies:
    maximum = False
    sha256 = hashlib.sha256()

    name = i.split(">")[0]
    version = (i.split("=")[-1]).strip()
    try:
        version = (version.split(",")[1]).strip()
        maximum = True
    except:
        version = version

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
        file = datafile["releases"][version][2] #Those that does not deal with OS only have 2 items in list
        for i in datafile["releases"][version]["url"]:
            # Never specify to look for 64 bit or 32 bit files, but SHOULD WORK
            if (platformType == "Darwin"):
                if ("macosx" in i) and ("cp310" not in i):
                    url = i
                    break
            elif (platformType == "Linux"):
                if ("linux" in i) and ("cp310" not in i):
                    url = i
                    break
            else:
                if ("win" in i and ("cp310" not in i)):
                    url = i
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
        # Path(path).unlink()
        print(f"Dependency {i} does not match the hash!")
    else:
        # Don't uncomment yet, kinda weird, it uninstalled some of my shit because i put latest version
        # It works but its an old way of doing it so need find improved way
        # pipmain(['install', path])
        print(f"Dependency {i} matches the hash! Successfully Installed & Deleted")
        # Path(path).unlink(missing_ok=True)