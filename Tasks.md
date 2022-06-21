# Tasks for securing the web application

---

## Jason

---

### Cryptographic Failures

#### Plan:
- Login and signup pages
- Storing of credit card
- Profile page (change credentials)
- Hashing of passwords
- Asymmetric encryption for sensitive information
- Host and use HTTPS

#### Implemented:
- Secure Flask Secret Key using `secrets.token_bytes(512)` (4096 bits)
  - Unlikely to be guessed ($2^{4096}$ possible keys)
  - Prevent session cookie from being tampered with
  - In the event that the key is leaked, the key can be simply rotated using [Google Cloud Secret Manager API](https://cloud.google.com/secret-manager)
- [Argon2](https://pypi.org/project/argon2-cffi/) for hashing passwords
  - Argon2 will generate a random salt using `os.urandom(16)` which is more secure than setting your own salt
  - Minimum requirement as of [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): 
    - 15728KB/15MiB of memory
    - 2 count of iterations 
    - 1 degree of parallelism
  - Argon2 default configurations:
    - 65536KB/64MiB of memory
    - 3 count of iterations
    - 4 degrees of parallelism when hashing
  - Which meets the OWASP minimum requirements
- Using [Google OAuth2](https://developers.google.com/identity/protocols/oauth2/web-server) for login/signup (removed the need for storing passwords)
- Encrypting the sensitive cookie values such as session identifier
  - Using RSAES-OAEP 4096 bit key with a SHA-512 digest (Asymmetric Encryption)
  - Preventing sensitive data from being sniffed and exposed such as the session identifier
- Encrypting the sensitive data in the database using Google's Symmetric Encryption Algorithm
  - 256-bit Advanced Encryption Standard (AES-256) keys in Galois Counter Mode (GCM), padded with Cloud KMS-internal metadata
  - Each user has a unique symmetric key for encryption and decryption
  - Encrypted the Argon2 hash of the password

---

### Identification and Authentication Failures

#### Plan:
- Brute forcing/credential stuffing logins
- Implement 2FA
- Invalidate session after several mins of inactivity
- Block weak passwords

#### Implemented:
- Minimum Password Complexity Policy using regex
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 digit
  - At least 1 special character
  - At least 10 characters
  - Not more than 2 repeated characters
- Blacklisting of known malicious IP addresses
- Verification of passwords if the passwords has been leaked in the dark web using [haveibeenpwned's api](https://haveibeenpwned.com/API/)
  - Verified whenever the user signs up or changes his/her password
- Maximum of 10 failed login attempts per account (will reset after 30 mins)
- Session timeout after 30 mins of inactivity
- 2 Factor Authentication using Google Authenticator Time-based OTP (TOTP)
- Using [Google OAuth2](https://developers.google.com/identity/protocols/oauth2/web-server) for authenticating users 
  - [More info on OAuth](https://owasp.org/www-pdf-archive/OWASP-NL_Chapter_Meeting201501015_OAuth_Jim_Manico.pdf)
  - Security of the login process will be handled by Google as the user has to sign in with Google
- Asymmetric encryption of session identifier in the cookie value (Using RSA)
  - Preventing the session identifier from being sniffed
- IP address based authentication
  - Checks against known IP addresses of users against the login request
  - If the IP address is not known, the user will be asked to authenticate himself/herself using a generated 6 digit TOTP code that is sent to the user's email

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

#### Implemented:
-

---

### Security Misconfiguration

#### Plan:
- Secret key to be dynamic and secure everytime the server starts
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
-

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
- Use SQL instead of shelve
- Prevent SQL injections
- Remember to use multithreading for writing account info to the SQL database

#### Implemented:
-

---

### Software and Data Integrity Failures

#### Plan:
- Implement hashing or digital signature whenever a user uploads something (User profile image, video upload for course creation, etc.)
- Fix deserialization vulnerability with pickle (shelve) by changing to SQL (You may have to do this first as we need to rely on you for the accounts)
- Ensure downloading/updating dependencies is not altered
    (check hash between original and downloaded files)

#### Implemented:
-

---