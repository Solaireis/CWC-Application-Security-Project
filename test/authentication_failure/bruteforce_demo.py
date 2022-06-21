import requests, threading
from lxml import html
from typing import Union

def req() -> Union[int, str]:
    url = "http://localhost:5000/login"
    data = {"email": "test@test.com", "password": "123123123"}
    r = requests.post(url, data=data)
    if (r.status_code == 200):
        # check for error messages such as "too many failed attempt" using xpath
        tree = html.fromstring(r.text)
        tooManyAttempts = tree.xpath("//div//h6[@class='warning_text' and text()[contains(., 'Too many failed login attempts, please try again later.')]]")
        if (len(tooManyAttempts) > 0):
            return "Account Locked!"

        failedLogin = tree.xpath("//div//h6[@class='warning_text' and text()[contains(., 'Please check your entries and try again!')]]")
        if (len(failedLogin) > 0):
            return "Failed Login!"

        # if no login error messages
        return "Login Successful!"

    return r.status_code

class MyThread(threading.Thread):
    def run(self):
        statusArr.append(req())

global statusArr
statusArr = []

threads = [MyThread() for _ in range(50)]

for t in threads:
    t.start()

for t in threads:
    t.join()

print(statusArr)

print("Number of requests:", len(statusArr))
print("Number of requests with 429 response:", statusArr.count(429))
print("Number of internal server errors:", statusArr.count(500))

print("\nVerdict:")

anyPrints = False
accountLocked = statusArr.count("Account Locked!")
if (accountLocked > 0):
    print(f"There {f'were {accountLocked}' if (accountLocked > 1) else 'was 1'} attempts with \"Too many failed login attempts\" message!")
    anyPrints = True

failedLogins = statusArr.count("Failed Login!")
if (failedLogins > 0):
    print(f"There {f'were {failedLogins}' if (failedLogins > 1) else 'was 1'} Failed Login attempts!")
    anyPrints = True

successfulLogins = statusArr.count("Login Successful!")
if (successfulLogins > 0):
    print(f"There {f'were {successfulLogins}' if (successfulLogins > 1) else 'was 1'} Successful Login attempts!")
    anyPrints = True

if (anyPrints is False):
    print("None...")