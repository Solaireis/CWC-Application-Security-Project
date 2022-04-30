# Tasks

### Secure Version

---

Jason: 
(Cryptographic Failures)
- Login and signup pages
- Storing of credit card
- Profile page (change credentials)
- Encryption of passwords
- Asymmetric encryption for sensitive information

(Identification and Authentication Failures)
- Brute forcing/credential stuffing logins
- Implement 2FA
- Invalidate session after several mins of inactivity
- Block weak passwords

---

Eden:
(Broken Access Control)
- Make a admin only file 
  - Make a admin only files (such as a csv file of admin account info, user base info, etc.)
- Validate access (deny by default) such as for admin pages, etc.
- Deny request to a user's purchase course link
- Block all read and write access to SQL database except for the web app

(Security Misconfiguration)
- Secret key to be dynamic and secure everytime the server starts
- Check if there's unnecessary features
- Showing too detailed error messages (such as in login pages)
- Check vulnerabilities in dependencies used
- Block users from access files outside of the web app
- Disallow default admin password such as "admin123"

---

Wei Ren:
(Insecure Design)
- Flask limiter
- implement reCaptcha (if you have the time to read docs :D)
- Fix errors
    - For insecure, you can allow user to buy nth num of a course
- Decide whether to use Flask login or the old style of session management

(Security Logging and Monitoring Failures)
- Implement logging
- Log all logins (successful and failed logins), access controls (when user tries to access a folder, etc.), server-side input failures (SQL query, etc.)
- Implement an algorithm to detect malicious accounts (created in same IP, etc.)
- Ensure logs can be used by log management solution software
- Ensure logs is not vulnerable to corruption (multithreading :D, SQL injections, etc.)
- Prevent all access except read access to admins (need to create a log page for admins)
- Alert the security teams and/or admins in an event of a live attack (DDoS)

---

Calvin:
(Injection)
- Use SQL instead of shelve
- Prevent SQL injections
- Remember to use multithreading for writing account info to the SQL database

(Software and Data Integrity Failures)
- Implement hashing or digital signature whenever a user uploads something (User profile image, video upload for course creation, etc.)
- Fix deserialization vulnerability with pickle (shelve) by changing to SQL (You may have to do this first as we need to rely on you for the accounts)
- Ensure downloading/updating dependencies is not altered
    (check hash between original and downloaded files)

---