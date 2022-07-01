# Tasks for securing the web application

---

## Jason

---

### Cryptographic Failures

#### Implemented:
- Secure Flask Secret Key using `secrets.token_bytes(512)` (4096 bits)
  - Unlikely to be guessed ($2^{4096}$ possible keys)
  - Prevent session cookie from being tampered with
  - In the event that the key is leaked, the key can be simply rotated using [Google Cloud Platform Secret Manager API](https://cloud.google.com/secret-manager)
- [Argon2](https://pypi.org/project/argon2-cffi/) for hashing passwords
  - Argon2 will generate a random salt using `os.urandom(nBytes)` which is more secure than setting your own salt
  - Minimum requirement as of [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): 
    - 15MiB of memory
    - 2 count of iterations 
    - 1 degree of parallelism
  - Default Argon2 configuration (Meets the minimum requirements):
    - 64MiB of memory
    - 3 count of iterations
    - 4 degree of parallelism
    - 16 bytes salt, `os.urandom(16)`
    - 32 bytes hash
    - Argon2id (hybrid type of Argon2i and Argon2d)
    - On average, the time taken to hash a password is about 0.05+ seconds.
  - Manually tweaked Argon2 configurations (Meets the minimum requirements):
    - 256MiB of memory
    - 12 count of iterations
    - 12 degrees of parallelism
    - 64 bytes salt, `os.urandom(64)`
    - 64 bytes hash
    - Argon2id (hybrid type of Argon2i and Argon2d)
    - On average, the time taken to hash a password is about 0.5+ seconds.
- Using [Google OAuth2](https://developers.google.com/identity/protocols/oauth2/web-server) for login/signup (removed the need for storing passwords)
- Encrypting the (temporarily stored) sensitive data in the session cookie such as secret token for TOTP (time-based one time password)
  - Using RSAES-OAEP 4096 bit key with a SHA-512 digest (Asymmetric Encryption)
    - 156 bits of security
  - Preventing sensitive data from being sniffed and exposed such as the session identifier
- Encrypting the sensitive data in the database using Google's Symmetric Encryption Algorithm
  - Using Google Cloud Platform KMS (Key Management Service) API
  - 256-bit Advanced Encryption Standard (AES-256) keys in Galois Counter Mode (GCM), padded with Cloud KMS-internal metadata
  - Each user has a unique symmetric key for encryption and decryption
  - Encrypted the Argon2 hash of the password
- Removed the need of storing credit/debit card information with the implementation of stripe as the payment gateway
- Made an asymmetric signing function capable of JWT feature for authorising sensitive actions such as reset password
  - Digitally signed using Elliptic Curve P-384 key SHA384 Digest 
    - Using Google Cloud Platform KMS (Key Management Service) API
    - 192 bits of security

---

### Identification and Authentication Failures

#### Implemented:
- Minimum Password Complexity Policy using regex
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 digit
  - At least 1 special character
  - At least 10 characters
  - Not more than 2 repeated characters
  - All must be fulfiled when checking with haveibeenpwned api status was not 200 OK/is down.
    - Acts as a fallback if the haveibeenpwned api is down.
- Blacklisting of known malicious IP Addresses
  - Mainly used for detecting bots with malicious intent
  - An ineffective mitigation but acts as last resort mitigation against attackers trying to brute force login or doing other malicious activities such as credential stuffing on the web application
  - Mainly uses this GitHub repository for the list of malicious IP Addresses: [ipsum](https://github.com/stamparm/ipsum)
- Verification of passwords if the passwords has been leaked in the dark web using [haveibeenpwned's api](https://haveibeenpwned.com/API/)
  - Verified when:
    - After a successful login
    - Sign up
    - Changing password
    - Resetting password
- Maximum of 6 failed login attempts per account (will reset after 30 mins)
  - In the event that the attacker tries to do a denial of service knowing that one could lock out authentic user:
    - An email will be sent to the user's email with a one-time link to unlock the account
    - Link uses a digitally signed token to prevent tampering
- Session Management Implementation:
  - Session identifier of 32 bytes (Unlikely to be guessed)
  - Session timeout after 30 mins of inactivity (If there were no request to the web server for 30 mins)
  - Check session identifier in the database and compare with the session identifier in the cookie
  - Check if the session cookie comes from the same IP address as the session identifier in the database
  - All mitigations above are aimed at mitigating the risk of session hijacking
- 2 Factor Authentication using Google Authenticator Time-based OTP (TOTP)
- Using [Google OAuth2](https://developers.google.com/identity/protocols/oauth2/web-server) for authenticating users 
  - [More info on OAuth](https://owasp.org/www-pdf-archive/OWASP-NL_Chapter_Meeting201501015_OAuth_Jim_Manico.pdf)
  - Security of the login process will be handled by Google as the user has to sign in with Google
- Securing the session cookie by setting the correct attributes such as HttpOnly, Secure, etc.
  - Preventing the cookie from being sniffed as it is only transmitted via HTTPS (Secure)
  - Preventing client-side scripts from accessing the cookie data (HttpOnly)
- IP address based authentication
  - Checks against known IP addresses of users against the login request
  - If the IP address is not known, the user will be asked to authenticate himself/herself using a generated 6 digit TOTP code that is sent to the user's email
  - The saved IP address will stay in the database until it has not been accessed on that IP address for more than 10 days
- Added reCAPTCHA on the login page
  - Prevent automated attacks such as
    - Credential stuffing attacks
    - Brute force attacks

---

## Eden

---

### Broken Access Control

#### Plan
- Make a admin only file 
  - Make a admin only files (such as a csv file of admin account info, user base info, etc.)
- Validate access (deny by default) such as for admin pages, etc.
- Deny request to a user's purchase course link
- Block all read and write access to SQL database except for the web app
- Work on integrating AWS Identity Provider with GCP Workforce Identification Pool
  - Since [google-sm.json](src/config_files/google-sm.json) is stored locally in the web file system, it is a security risk as one might get a copy and have access to all the secrets stored in Google Secret Manager API.


#### Implemented:
-

---

### Security Misconfiguration

#### Plan:
- Check if there's unnecessary features
- Showing too detailed error messages (such as in login pages)
- Check vulnerabilities in dependencies used
- Block users from access files outside of the web app
- Disallow default admin password such as "admin123"

#### Implemented:
-

---

## Wei Ren

---

### Insecure Design

#### Plan:
- Flask limiter
- implement reCaptcha (if you have the time to read docs :D)
- Fix errors
    - For insecure, you can allow user to buy nth num of a course
- Decide whether to use Flask login or the old style of session management

#### Implemented:
- reCAPTCHA on signup page

---

### Security Logging and Monitoring Failures

#### Plan:
- Implement logging
- Log all logins (successful and failed logins), access controls (when user tries to access a folder, etc.), server-side input failures (SQL query, etc.)
- Implement an algorithm to detect malicious accounts (created in same IP, etc.)
- Ensure logs can be used by log management solution software
- Ensure logs is not vulnerable to corruption (multithreading :D, SQL injections, etc.)
- Prevent all access except read access to admins (need to create a log page for admins)
- Alert the security teams and/or admins in an event of a live attack (DDoS)

#### Implemented:
-

---

## Calvin

---

### Injection

#### Plan:
- Avoid Bad Coding Practices that lead to Injection Attacks
- Prevent SQL injections
- Remember to use multithreading for writing account info to the SQL database

#### Implemented:
- SQL Injection
  - Implement Parameterised Queries
  - Implement Stored Procedures
- Server Side Template Injection
  - Avoid using render_template_string(template)
    - render_template() is safer because users are unable to modify the template
- Code Injection
  - Avoid using eval()
- Cross Site Scripting
  - Avoid using render_template_string(template) [(Example)](https://semgrep.dev/r?q=python.flask.security.unescaped-template-extension.unescaped-template-extension)
  - In Jinja, everything is escaped by default except for values explicitly marked with the |safe filter.
    - If required use Markup()
  - Using url_for() in href tags instead of passing in variables 
  - Implemented CSP, but only for scripts
    - Nonce-in only for inline scripts, those inline scripts without the nonce tags will not run properly
    - script src in csp shows all the scripts allowed to be taken from external sources

---

### Software and Data Integrity Failures

#### Plan:
- Implement hashing or digital signature whenever a user uploads something (User profile image, video upload for course creation, etc.)
- Fix deserialization vulnerability with pickle (shelve) by changing to SQL (You may have to do this first as we need to rely on you for the accounts)
- Ensure downloading/updating dependencies is not altered
    (check hash between original and downloaded files)

#### Implemented:
- Implemented MySQL
- Comparing Hashes of Packages, before pip installing them

---