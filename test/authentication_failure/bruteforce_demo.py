import platform
from lxml import html
import asyncio, aiohttp

async def fetch(url:str, session:aiohttp.ClientSession) -> dict:
    # get the _csrf_token value from the login page
    data = {"email": "demo@test.com", "password": "123123123"}
    async with session.get(url) as r:
        htmlResponse = await r.text()
        if (r.status != 200):
            return htmlResponse, r.status

        # Retrieve the CSRF token from the login page
        htmlTree = html.fromstring(htmlResponse)
        csrfToken = htmlTree.xpath("//input[@name='_csrf_token']/@value")
        data["_csrf_token"] = csrfToken[0]

    async with session.post(url, json=data) as r:
        return await r.text(), r.status

async def send_requests(urls:list) -> list:
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as session:
        # Send a get request and retrieve 
        # the CSRF token cookie value from the login page
        async with session.get(urls[0]) as r:
            if (r.status != 200):
                print("Initial GET request failed!")
                return []
            cookies = session.cookie_jar.filter_cookies(urls[0].rsplit("/", 1)[0])
            csrfCookie = {k: v for k, v in cookies.items() if (k == "_csrf_token")}

        # add the csrfToken cookie to the session
        session.cookie_jar.update_cookies(csrfCookie)

        return await asyncio.gather(*[fetch(url, session) for url in urls])

def get_result(responses:list) -> list:
    statusArr = []
    for r in responses:
        statusCode = r[1]
        htmlResponse = r[0]
        if (statusCode != 200):
            statusArr.append(statusCode)
        else:
            # check for error messages such as "too many failed attempt" using xpath
            htmlTree = html.fromstring(htmlResponse)

            # using xpath to find the error message
            tooManyAttempts = htmlTree.xpath("//div//h6[@class='warning_text' and text()[contains(., 'Too many failed login attempts, please try again later.')]]")
            failedLogin = htmlTree.xpath("//div//h6[@class='warning_text' and text()[contains(., 'Please check your entries and try again!')]]")
            recaptchaMessage = htmlTree.xpath("//div//h6[@class='warning_text' and text()[contains(., 'Please verify that you are not a bot!')]]")

            if (len(tooManyAttempts) > 0):
                statusArr.append("Account Locked!")
            elif (len(failedLogin) > 0):
                statusArr.append("Failed Login!")
            elif (len(recaptchaMessage) > 0):
                statusArr.append("Recaptcha Error!")
            else:
                statusArr.append("Unknown Error!")

    return statusArr

def main() -> None:
    urlArr = ["https://localhost:8080/login"] * 50

    if (platform.system() == "Windows"):
        # A temporary fix for ProactorBasePipeTransport issues 
        # on Windows OS Machines caused by aiohttp
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    responseArr = asyncio.run(send_requests(urlArr))
    statusArr = get_result(responseArr)

    print("Verdict:")
    print("1. There were", len(statusArr), "requests to the login page.")
    print("2.", statusArr.count(429), "out of the", len(statusArr), "requests were rate limited.")
    print("3. There were", statusArr.count(500), "internal server errors.")

    accountLocked = statusArr.count("Account Locked!")
    if (accountLocked > 0):
        print(f"4. There {f'were {accountLocked}' if (accountLocked > 1) else 'was 1'} attempts with \"Too many failed login attempts\" message.")
    else:
        print("4. There were no attempts with \"Too many failed login attempts\" message.")

    failedLogins = statusArr.count("Failed Login!")
    if (failedLogins > 0):
        print(f"5. There {f'were {failedLogins}' if (failedLogins > 1) else 'was 1'} Failed Login attempts!")
    else:
        print("5. There were no Failed Login attempts!")

    successfulLogins = statusArr.count("Login Successful!")
    if (successfulLogins > 0):
        print(f"6. There {f'were {successfulLogins}' if (successfulLogins > 1) else 'was 1'} Successful Login attempts!")
    else:
        print("6. There were no Successful Login attempts!")

    csrfErrors = statusArr.count(403)
    if (csrfErrors > 0):
        print(f"7. There {f'were {csrfErrors}' if (csrfErrors > 1) else 'was 1'} CSRF errors due to missing or invalid CSRF token!")
    else:
        print("7. There were no CSRF errors due to missing or invalid CSRF token!")

    recaptchaErrors = statusArr.count("Recaptcha Error!")
    if (recaptchaErrors > 0):
        print(f"8. There {f'were {recaptchaErrors}' if (recaptchaErrors > 1) else 'was 1'} Recaptcha errors!")
    else:
        print("8. There were no reCAPTCHA enterprise message!")

    unknownErrors = statusArr.count("Unknown Error!")
    if (unknownErrors > 0):
        print(f"9. There {f'were {unknownErrors}' if (unknownErrors > 1) else 'was 1'} unknown errors!")
    else:
        print("9. There were no unknown errors!")

if (__name__ == "__main__"):
    main()