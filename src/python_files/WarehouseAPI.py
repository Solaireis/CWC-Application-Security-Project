# import third party libraries
import requests

# import python standard libraries
import hashlib
from pathlib import Path
import shutil
import platform
from pip._internal import main as pipmain # Old Pip Wrapper, for now it works

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

# Work in progress
# for i in dependencies:
#     name = i.split(">")[0]
#     try:
#         version = i.split("<")[1]

#     except:
#         version = (i.split("=")[-1]).strip()
#         datafile = (requests.get(f"https://pypi.org/pypi/{name}/json", stream=True, headers=headers, timeout=10)).json()
#         file = datafile["releases"][version][0]
#         url = file["url"]
#         filename = url.split("/")[-1]
#         hashed = file["digests"]["sha256"]
#         path = f"{packagedir}/{filename}"

#         with requests.get(url, stream=True, headers=headers, timeout=10) as r:
#             with open(path, "wb") as f:
#                 shutil.copyfileobj(r.raw, f)

# For now does not check for version, and which whl file to download
#Plan to take latest valid version as well
for i in dependencies:
    sha256 = hashlib.sha256()

    name = i.split(">")[0]
    version = (i.split("=")[-1]).strip()
    try:
        x = version.split(",")[1]
        version = (version.split(",")[0]).strip()
    except:
        version = version

    datafile = (requests.get(f"https://pypi.org/pypi/{name}/json", stream=True, headers=headers, timeout=10)).json()
    file = datafile["releases"][version][0]
    url = file["url"]
    filename = url.split("/")[-1]
    hashed = file["digests"]["sha256"]
    path = f"{packagedir}/{filename}"

    with requests.get(url, stream=True, headers=headers, timeout=10) as r:
        with open(path, "wb") as f:
            shutil.copyfileobj(r.raw, f)

    with open(path, 'rb') as f:
        data = f.read()
        sha256.update(data)

    if (sha256.hexdigest() != hashed):
        Path(path).unlink()
        print(f"Dependency {i} does not match the hash!")
    else:
        # Don't uncomment yet, kinda weird, it uninstalled some of my shit because i put latest version
        # It works but its an old way of doing it so need find improved way
        # pipmain(['install', path])
        print(f"Dependency {i} matches the hash! Successfully Installed & Deleted")
        Path(path).unlink(missing_ok=True)

