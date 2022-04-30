# IT-2555 Application Security Assignment Self-Analysis

Refer below for the definition of each OWASP category and its potential areas that can be applied in CourseFinity.

## Table of Contents
OWASP Top 10 (Web Application) 2021
- [A01:2021 Broken Access Control](#1)
- [A02:2021 Cryptographic Failures](#2)
- [A03:2021 Injection](#3)
- [A04:2021 Insecure Design](#4)
- [A05:2021 Security Misconfiguration](#5)
- [A06:2021 Vulnerable and Outdated Components](#6)
- [A07:2021 Identification and Authentication Failures](#7)
- [A08:2021 Software and Data Integrity Failures](#8)
- [A09:2021 Security Logging and Monitoring Failures](#9)
- [A10:2021 Server-Side Request Forgery (SSRF)](#10)

---

## OWASP Top 10 (Web Application) 2021

<p id="1"></p>

1. [A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
   - Access control enforces policy such that users cannot act outside of their intended permissions. 
   - Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.

   - Possible areas in our web application are:
     - Admin pages not secured against public access.
     - Admin owned files can be found through directory traversal attacks.
     - Changing the session cookie value to impersonate another user.
     - Videos from teachers can be viewed through directory traversal attacks (even without buying the videos).

<p id="2"></p>

2. [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
   - Shifting up one position to #2, previously known as Sensitive Data Exposure, which is more of a broad symptom rather than a root cause, the focus is on failures related to cryptography (or lack thereof). 
   - Which often lead to exposure of sensitive data. Notable Common Weakness Enumerations (CWEs) included are:
     - CWE-259: Use of Hard-coded Password
     - CWE-327: Broken or Risky Crypto Algorithm
     - CWE-331 Insufficient Entropy.
   - The first thing is to determine the protection needs of data in transit and at rest. 
   - For example, passwords, credit card numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls under privacy laws, e.g., EU's General Data Protection Regulation (GDPR), or regulations, e.g., financial data protection such as PCI Data Security Standard (PCI DSS).

   - Possible areas in our web application are:
     - Account recover process where the password is sent in plaintext
       - Though not sure one would fix it :thonk:
     - Password hashing is not secure enough.
     - Password stored in plain text.
     - Salting vs Peppering
       - Are the salt or peppers weak?
     - Personal information stored (phone numbers) for payment processing is stored in plain text.
       - Encryption key must be stored securely!
       - Must not decrypt and send the data back in plaintext!
     - HTTPS BEST SECURITY

<p id="3"></p>

3. [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
   - An application is vulnerable to attack when:
     - User-supplied data is not validated, filtered, or sanitized by the application.
     - Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.
     - Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.
     - Hostile data is directly used or concatenated. The SQL or command contains the structure and malicious data in dynamic queries, commands, or stored procedures.

   - Possible areas in our web application are:
     - Convert web application persistent storage to SQL from Shelve (pickle which has a deserialisation vulnerability).
     - Fix SQL injection vulnerabilities.
       - Input validation
       - Escape special characters
       - Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in the database.

<p id="4"></p>

4. [A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
   - Insecure design is a broad category representing different weaknesses, expressed as “missing or ineffective control design.” Insecure design is not the source for all other Top 10 risk categories.
   - There is a difference between insecure design and insecure implementation. 
     - We differentiate between design flaws and implementation defects for a reason, they have different root causes and remediation.
   - A secure design can still have implementation defects leading to vulnerabilities that may be exploited.
   - An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks. 
   - One of the factors that contribute to insecure design is the lack of business risk profiling inherent in the software or system being developed, and thus the failure to determine what level of security design is required.

   - Possible areas in our web application are:
     - Bot protection
       - Prevent bots from accessing the application and downloading videos sold by teachers (web scraping, etc.)
       - Use reCaptcha
     - Find unreported errors that can break the web application such as:
       - Buying videos but it allows user to buy multiple times (should be a one-time thing only)
       - Replacing old codes with a newer and more secure code
         - Using libraries such as Flask Login instead of coding the session management yourself.

<p id="5"></p>

5. [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
   - The application might be vulnerable if the application is:
     - Missing appropriate security hardening across any part of the application stack or improperly configured permissions on cloud services.
     - Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
     - Default accounts and their passwords are still enabled and unchanged.
     - Error handling reveals stack traces or other overly informative error messages to users.
     - For upgraded systems, the latest security features are disabled or not configured securely.
     - The security settings in the application servers, application frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases, etc., are not set to secure values.
     - The server does not send security headers or directives, or they are not set to secure values.
     - The software is out of date or vulnerable (see [A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)).
   - Without a concerted, repeatable application security configuration process, systems are at a higher risk.

   - Possible areas in our web application are:
     - Unused pages that are also active in the application.
     - Unnecessary features that are enabled or installed.
       - Such as having unnecessary ports, services, pages, accounts, or privileges.
         - E.g. Admins having the features to delete another admin.
     - Showing error messages with too much information
       - Login errors (tells user which entered information is incorrect)
         - Allows brute force attacks to guess accounts credentials easily.
         - Allows enumeration attacks to guess which emails or passwords are in use.
     - Dependencies has a known vulnerability.
       - E.g. outdated libraries, outdated frameworks, outdated databases, outdated servers, etc.
     - Secret Key is static and is easily guessable.
       - Used for the flask web application session.
     - Directory traversal attacks (Directories did not deny by default)
         - Allows users to access files outside of the web application.
     - Admin console python file sets the admin passwords to a default password.
       - Attackers can brute force and login to the web application as an admin.

<p id="6"></p>

6. [A06:2021 – Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
   - You are likely vulnerable:
     - If you do not know the versions of all components you use (both client-side and server-side). This includes components you directly use as well as nested dependencies.
     - If the software is vulnerable, unsupported, or out of date. This includes the OS, web/application server, database management system (DBMS), applications, APIs and all components, runtime environments, and libraries.
     - If you do not scan for vulnerabilities regularly and subscribe to security bulletins related to the components you use.
     - If you do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion. This commonly happens in environments when patching is a monthly or quarterly task under change control, leaving organizations open to days or months of unnecessary exposure to fixed vulnerabilities.
     - If software developers do not test the compatibility of updated, upgraded, or patched libraries.
     - If you do not secure the components’ configurations (see [A05:2021-Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)).

   - Possible areas in our web application are:
     - Running outdated dependencies.
     - Have a system to alert admins about vulnerable dependencies used.
     - Obtain components from official sources over secure links (when downloading a dependency, etc.)
     - Check for dependencies that are no longer maintained
       - E.g. flask_mail has not been updated for a very long time since 2014.
         - Newer and maintained dependency of [flask_mail](https://github.com/mattupstate/flask-mail) is [flask_mailman](https://github.com/waynerv/flask-mailman).

<p id="7"></p>

7. [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
   - Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. 
   - There may be authentication weaknesses if the application:
     - Permits automated attacks such as credential stuffing, where the attacker has a list of valid usernames and passwords.
     - Permits brute force or other automated attacks.
     - Permits default, weak, or well-known passwords, such as "Password1" or "admin/admin".
     - Uses weak or ineffective credential recovery and forgot-password processes, such as "knowledge-based answers," which cannot be made safe.
     - Uses plain text, encrypted, or weakly hashed passwords data stores (see [A02:2021-Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)).
     - Has missing or ineffective multi-factor authentication.
     - Exposes session identifier in the URL.
     - Reuse session identifier after successful login.
     - Does not correctly invalidate Session IDs. User sessions or authentication tokens (mainly single sign-on (SSO) tokens) aren't properly invalidated during logout or a period of inactivity

   - Possible areas in our web application are:
     - Allow attackers to brute force/automated attacks at the login page
       - No flask limiter by IP Addresses, etc.
     - Allows [credential stuffing attacks](https://www.imperva.com/learn/application-security/credential-stuffing/) where attackers have a list of valid usernames and passwords and the attacker can use them to login.
       - Prompt user to authenticate everytime when the user is logged via a new IP Address (if user do not have 2FA setup).
       - Implement 2FA Authnetication.
       - Use reCaptcha/CAPTCHA!
     - 2FA Authentication is not implemented or implemented ineffectively.
       - Currently, the QR code for the setup key is stored in the server for 15mins, might want a solution where the QR code will not be stored but still sent to the user's browser.
         - Search up [blob](https://developer.mozilla.org/en-US/docs/Web/API/Blob)
     - Invalidate the user's session after several minutes of inactivity.
       - Will have to modify the flask session,
         - [Click me](https://www.bonser.dev/blog/basic-flask-session-timeout-on-inactivity) for a helpful blog that teaches you about this!
     - Check if the url exposes a session identifier.
       - E.g. if the user is logged in, the url will contain the session identifier.
     - Allow weak passwords.
       - E.g. "Password1" or "admin/admin"
     - Uses weak or ineffective credential recovery and forgot-password processes, such as "knowledge-based answers," which cannot be made safe.

<p id="8"></p>

8. [A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
   - Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. 
   - An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs). 
   - An insecure CI/CD pipeline can introduce the potential for unauthorized access, malicious code, or system compromise. 
   - Lastly, many applications now include auto-update functionality, where updates are downloaded without sufficient integrity verification and applied to the previously trusted application. 
   - Attackers could potentially upload their own updates to be distributed and run on all installations. 
   - Another example is where objects or data are encoded or serialized into a structure that an attacker can see and modify is vulnerable to insecure deserialization.
  
   - Possible areas in our web application are:
     - Use digital signatures or similar mechanisms to verify if uploaded files are not altered!
       - The profile images of users
       - The videos uploaded by the teachers.
     - Ensure libraries, frameworks, and modules are secure and highly trusted by others!
     - Change from shelve to SQL database.
       - As shelve is built on top of pickle and pickle is not secure during deserialization as if the pickled file contained malicious codes, it may run it.

<p id="9"></p>

9. [A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
   - Returning to the OWASP Top 10 2021, this category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time:
     - Auditable events, such as logins, failed logins, and high-value transactions, are not logged.
     - Warnings and errors generate no, inadequate, or unclear log messages.
     - Logs of applications and APIs are not monitored for suspicious activity.
     - Logs are only stored locally.
     - Appropriate alerting thresholds and response escalation processes are not in place or effective.
     - Penetration testing and scans by dynamic application security testing (DAST) tools (such as OWASP ZAP) do not trigger alerts.
     - The application cannot detect, escalate, or alert for active attacks in real-time or near real-time.

   - Possible areas in our web application are:
     - Logging is not implemented or implemented ineffectively.
     - Log all login, access control, server-side input failures.
     - Log suspicious or malicious accounts
       - Need an algorithm to detect if the user is a malicious account.
     - Ensure logs are generated in a format that log management solution can handle.
     - Ensure logs are not vulnerable to injections or attacks.
     - Prevent tampering with the log files.
     - Alert the security teams in an event of suspicious activity (in real-time)

<p id="10"></p>

10. [A10:2021 – Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
   - SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. 
   - It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).
   - As modern web applications provide end-users with convenient features, fetching a URL becomes a common scenario.
   - As a result, the incidence of SSRF is increasing. 
   - Also, the severity of SSRF is becoming higher due to cloud services and the complexity of architectures.

   - Possible areas in our web application are:
     - Disable HTTP redirections (requires hosting on firebase)
     - Sanitise and validate all client-supplied input data.
     - Ensure consistent URLs
