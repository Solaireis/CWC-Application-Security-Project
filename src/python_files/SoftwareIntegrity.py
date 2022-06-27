# import third party libraries
import requests

# import python standard libraries
import hashlib
from pathlib import Path
import shutil
import platform
from pip._internal import main as pipmain # Old Pip Wrapper, for now it works


"""
tar.gz files means file downloaded is based of system:

fixing
"""
platforms = {"Darwin": 0, "Linux": 1, "Windows": 2}
platformType = platform.system()


headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
} 

hashes = {
    "https://files.pythonhosted.org/packages/e4/9f/c3937d4babe62504b874d4bf2c0d85aa69c7f59fa84cf6050f3b9dc5d83e/APScheduler-3.9.1-py2.py3-none-any.whl": "ddc25a0ddd899de44d7f451f4375fb971887e65af51e41e5dcf681f59b8b2c9a",
    "https://files.pythonhosted.org/packages/a8/07/946d5a9431bae05a776a59746ec385fbb79b526738d25e4202d3e0bbf7f4/argon2_cffi-21.3.0-py3-none-any.whl":
    "8c976986f2c5c0e5000919e6de187906cfd81fb1c72bf9d88c01177e77da7f80",
    "https://files.pythonhosted.org/packages/a6/20/758694021228af5a971660fbc0a2480e59bfbaca77d2d33ce6916c392bf2/dicebear-0.4.15-py3-none-any.whl":"b5ca1f206062ea5643c069c8e56a51b0f6d48e07a46c82869d5d8def4fc6fabf",
    "https://files.pythonhosted.org/packages/6b/d2/c587a9cd8473041fd138b213fa12581a4e039d260cf24dfa07f5c9de78e4/email_validator-1.2.1-py2.py3-none-any.whl":
    "c8589e691cf73eb99eed8d10ce0e9cbb05a0886ba920c8bcb7c82873f4c5789c",
    "https://files.pythonhosted.org/packages/ba/76/e9580e494eaf6f09710b0f3b9000c9c0363e44af5390be32bb0394165853/Flask-2.1.2-py3-none-any.whl":
    "fad5b446feb0d6db6aec0c3184d16a8c1f6c3e464b511649c8918a9be100b4fe",
    "https://files.pythonhosted.org/packages/cd/fc/7079408353407c32a45b8efa948b6e7e1580c4e89dbe0547e91f176a46b7/Flask_Limiter-2.4.6-py3-none-any.whl":"2f0cfc25335f07f47bc3b2d49c17c2dbc380188ccf2ff1501680812b6f45fe61",
    "https://files.pythonhosted.org/packages/bc/c3/f068337a370801f372f2f8f6bad74a5c140f6fda3d9de154052708dd3c65/Jinja2-3.1.2-py3-none-any.whl":"6088930bfe239f0e6710546ab9c19c9ef35e29792895fed6e6e31a023a182a61",
    "https://files.pythonhosted.org/packages/41/5b/2209eba8133fc081d3ffff02e1f6376e3117e52bb16f674721a83e67e68e/requests-2.28.0-py3-none-any.whl":"bc7861137fbce630f17b03d3ad02ad0bf978c844f3536d0edda6499dafce2b6f",
    "https://files.pythonhosted.org/packages/83/63/15ce47ede5b03657e920f3f006e56ca9a16f7873978146f2f77e297bdd22/CacheControl-0.12.11-py2.py3-none-any.whl":"2c75d6a8938cb1933c75c50184549ad42728a27e9f6b92fd677c3151aa72555b",
    ("https://files.pythonhosted.org/packages/fe/ed/6ccef315991b33c93fb5a461d0e93b2813f09f7aee2171620905c1e98062/Pillow-9.1.1-pp38-pypy38_pp73-macosx_10_10_x86_64.whl","https://files.pythonhosted.org/packages/b0/ae/3974e657120d25dd5291b7a4c5212d9a1657f6d9a99f086a3332f8336b04/Pillow-9.1.1-pp38-pypy38_pp73-manylinux_2_17_x86_64.manylinux2014_x86_64.whl","https://files.pythonhosted.org/packages/b6/9e/03d75eee28bb6413f5dd170d480a4ab306ee7c7368e97eac02dea62ae3be/Pillow-9.1.1-pp38-pypy38_pp73-win_amd64.whl"):("6e760cf01259a1c0a50f3c845f9cad1af30577fd8b670339b1659c6d0e7a41dd","937a54e5694684f74dcbf6e24cc453bfc5b33940216ddd8f4cd8f0f79167f765","baf3be0b9446a4083cc0c5bb9f9c964034be5374b5bc09757be89f5d2fa247b8"),
    # "https://files.pythonhosted.org/packages/43/6e/59853546226ee6200f9ba6e574d11604b60ad0754d2cbd1c8f3246b70418/Pillow-9.1.1.tar.gz":"7502539939b53d7565f3d11d87c78e7ec900d3c72945d4ee0e2f250d598309a0",
    "https://files.pythonhosted.org/packages/e9/86/b2ede1d87122a6d4da86d84cc35d0e48b4aa2476e4281d06101c772c1961/setuptools-62.6.0-py3-none-any.whl":"c1848f654aea2e3526d17fc3ce6aeaa5e7e24e66e645b5be2171f3f6b4e5a178",
    "https://files.pythonhosted.org/packages/eb/2e/199a0edf6577af771a68fbd950d98f0c1a16bb5fa956e45772005318c702/WTForms-3.0.1-py3-none-any.whl":"837f2f0e0ca79481b92884962b914eba4e72b7a2daaf1f939c890ed0124b834b",
    "https://files.pythonhosted.org/packages/db/45/d3d05de6decb58bd88626d75d9ef43ac02ecc85a5f1ead20cf70ca6fbe27/phonenumbers-8.12.50-py2.py3-none-any.whl":"56713403b4160b59ea1fef4e842ddeb70931055146d794d371b60cd4b5f05fb8",
    "https://files.pythonhosted.org/packages/94/9f/31f33cdf3cf8f98e64c42582fb82f39ca718264df61957f28b0bbb09b134/qrcode-7.3.1.tar.gz":"375a6ff240ca9bd41adc070428b5dfc1dcfbb0f2507f1ac848f6cded38956578",
    "https://files.pythonhosted.org/packages/a5/cd/9114b5116a9bfbf7133e79f2f12c31a8611a689849a1a990fe5586c08526/pyotp-2.6.0-py2.py3-none-any.whl":"9d144de0f8a601d6869abe1409f4a3f75f097c37b50a36a3bf165810a6e23f28",
    ("https://files.pythonhosted.org/packages/dc/29/57cbcf4f38546d6558b380a1ac6e3d8f91ff6acb262ef2fd26d6dc25f935/cryptography-37.0.2-pp39-pypy39_pp73-macosx_10_10_x86_64.whl","https://files.pythonhosted.org/packages/16/cd/c6af461f422db83ec125b9d1fb3cccfcf796b9526017ab347fe7a4fdc629/cryptography-37.0.2-pp39-pypy39_pp73-manylinux_2_24_x86_64.whl","https://files.pythonhosted.org/packages/b0/c9/433457e9c94770c21f4b61594d8d3193bcb659de4423b982f4a29bf10b18/cryptography-37.0.2-pp39-pypy39_pp73-win_amd64.whl"):("1f3bfbd611db5cb58ca82f3deb35e83af34bb8cf06043fa61500157d50a70982","dc26bb134452081859aa21d4990474ddb7e863aa39e60d1592800a8865a702de","3b8398b3d0efc420e777c40c16764d6870bcef2eb383df9c6dbb9ffe12c64452"),
    # "https://files.pythonhosted.org/packages/51/05/bb2b681f6a77276fc423d04187c39dafdb65b799c8d87b62ca82659f9ead/cryptography-37.0.2.tar.gz":"f224ad253cc9cea7568f49077007d2263efa57396a2f2f78114066fd54b5c68e",
    "https://files.pythonhosted.org/packages/f3/2d/02562c81c0cbc787c2547db4d30b53c2c4f0a2c9368f7ec9aa0dc7b42fe6/google_api_python_client-2.51.0-py2.py3-none-any.whl":"b444f839bed289ecfe30950ea1cd15b7e7976d8cf9f0a3c778037ae3fb030df3",
    "https://files.pythonhosted.org/packages/ba/db/721e2f3f32339080153995d16e46edc3a7657251f167ddcb9327e632783b/google_auth_httplib2-0.1.0-py2.py3-none-any.whl":"31e49c36c6b5643b57e82617cb3e021e3e1d2df9da63af67252c02fa9c1f4a10",
    "https://files.pythonhosted.org/packages/f8/93/aa9e5c46c955758ec9f08779e78838f7e041cbef8338ac9e490465aa4947/google_auth_oauthlib-0.5.2-py2.py3-none-any.whl":"6d6161d0ec0a62e2abf2207c6071c117ec5897b300823c4bb2d963ee86e20e4f",
    "https://files.pythonhosted.org/packages/5d/72/6951d095a9b7b618e975547108c02308e0dba16004077dc9a32c52f1d4b2/google_cloud_secret_manager-2.11.1-py2.py3-none-any.whl":"41c837a583b904a134e65c2347b60009a10ead00dc040db8570b73bc78a6777f",
    "https://files.pythonhosted.org/packages/26/b4/05fecd87f8280af687e98489663fc67a5faadd1cb2c0ad8e8c8820941067/google_cloud_logging-3.1.2-py2.py3-none-any.whl":"702b69b01c4b98c50a4e4e7cbe12309de8c6685e99ec100c0c902e1765a45e92",
    "https://files.pythonhosted.org/packages/2b/75/54335429bb91f9d04f8b84b9f084d4cbff56c89145b56fd3a94d05d0c832/google_cloud_recaptcha_enterprise-1.7.1-py2.py3-none-any.whl":"ed523e876ffbe10584296f63633995bd59052a98a9605720d397364472b38bf8",
    "https://files.pythonhosted.org/packages/3e/52/ff9012efaa5e0c7101fac5d6790efe8b9912768ade1bd9fac56212233dfb/cloud_sql_python_connector-0.6.2-py2.py3-none-any.whl":"fe62e2fdb3f61539084a2135bfbe1a75c444fc8cace403e4f243ff51384db20b",
    "https://files.pythonhosted.org/packages/1e/76/aba85f1c4693a23c9bdb0c1b0c68d9a275f5faaf51b3af3e3a37062c07d6/google_cloud_kms-2.11.2-py2.py3-none-any.whl":"50dd2dc85968f14252333e01d231a03e5745279fe242cc046a488986fb55d5b6",
    ("https://files.pythonhosted.org/packages/56/26/c73a35fb8dc0a4715faac26108d543c0429a6bfced21de6e90615b2d2600/google_crc32c-1.3.0-pp37-pypy37_pp73-macosx_10_9_x86_64.whl","https://files.pythonhosted.org/packages/cb/eb/ccdf6b3a706b92955da122a75400f3759fefd63b8e601b816fc32d056584/google_crc32c-1.3.0-pp37-pypy37_pp73-manylinux_2_17_aarch64.manylinux2014_aarch64.whl","https://files.pythonhosted.org/packages/af/f0/80d52367f33565e2975c2a264ab9692f8e9d78004e475c4a8d1ece565d65/google_crc32c-1.3.0-pp37-pypy37_pp73-win_amd64.whl"):("fc28e0db232c62ca0c3600884933178f0825c99be4474cdd645e378a10588125","891f712ce54e0d631370e1f4997b3f182f3368179198efc30d477c75d1f44942","7f6fe42536d9dcd3e2ffb9d3053f5d05221ae3bbcefbe472bdf2c71c793e3183"),
    # "https://files.pythonhosted.org/packages/db/de/477cdcfd3ba2877cdf798f0328ea6aa79b2e632d169f5099d6240c4c4ebf/google-crc32c-1.3.0.tar.gz":"276de6273eb074a35bc598f8efbc00c7869c5cf2e29c90748fccc8c898c244df",
    "https://files.pythonhosted.org/packages/7d/c1/653af0e0302119e09fc38d12d1d5cf36b0b72a63486882745176055f3fca/flask_talisman-1.0.0-py2.py3-none-any.whl":"be2767b6b2bc11b36bf9a0e09ffa10622fbe0d971fd7057a843f82cd795a854b",
    "https://files.pythonhosted.org/packages/49/16/674f057123346cd737bc086e7a8fd2695833edb53f98e4e0b0ef5dce3984/Flask_SeaSurf-1.1.1-py3-none-any.whl":"f70e58b3b5e8fa9a928fe6b8e7a01b953d67cb9b7bde1a54d1ec95e40fcc2ade",
    "https://files.pythonhosted.org/packages/8d/b8/83947d23fa14dd72b22b48c29e8e1526d7521db88ff7eea25e07ec705e40/stripe-3.4.0-py2.py3-none-any.whl":"baead81078913f170df57b2c5ffb05f0b6a1c6eaea8dd9a25922c7025916768d",
    "https://files.pythonhosted.org/packages/8b/ac/24c4cf8db22004aaf91243e9789eb0bb75f7c170da22406549ee18d41313/ipinfo-4.2.1-py3-none-any.whl":"a4ec65647e7f973586090bac286b624f1fba496cda8cd94ae9a1c3ec239d0948",
}

"""
Temporary
see if link & hashes match

count = 1
for i in hashes:
    result = requests.get(i)
    hashedresult = sha256(result.content).hexdigest()
    if (hashedresult == hashes[i]):
        print(count)
        count += 1
"""
dirname = Path(__file__).absolute().parent.parent.joinpath("python_packages")
dirname.mkdir(parents=True, exist_ok=True)

for i in hashes:
    if (isinstance(i, tuple)):
        i = i[platforms[platformType]]
    x = i.split("/")
    path = f"{dirname}/{x[-1]}"
    with requests.get(i, stream=True, headers=headers, timeout=10) as r:
        with open(path, "wb") as f:
            shutil.copyfileobj(r.raw, f)

for i in hashes:
    sha256 = hashlib.sha256()
    hashed = hashes[i]
    if (isinstance(i, tuple)):
        hashed = hashes[i][platforms[platformType]]
        i = i[platforms[platformType]]
    x = i.split("/")
    path = f"{dirname}/{x[-1]}"
    with open(path, 'rb') as f:
        data = f.read()
        sha256.update(data)
    
    if (sha256.hexdigest() != hashed):
        Path(path).unlink()
        print(f"File from {i} does not match the hash!")
    else:
        # Don't uncomment yet, kinda weird, it uninstalled some of my shit because i put latest version
        # It works but its an old way of doing it so need find improved way
        pipmain(['install', path])
        print(f"File from {i} matches the hash! Successfully Installed & Deleted")
        Path(path).unlink()
