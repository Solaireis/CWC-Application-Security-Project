<h1 align="center">
<img src="https://raw.githubusercontent.com/KJHJason/App-Development-Project/main/static/images/common/logo.png" width="500px" height="150px" alt="CourseFinity Logo">
<br>
CourseFinity Web Application using Flask
<br>
(Requires Python 3.8 and above)
</h1>
## Forked Project for App Security Group project purposes
## Nanyang Polytechnic Y1 App Development Group Project [4 members]
This project consists of us making a web application using Flask as its framework.

**Group Members:**
>1. Jason (Group Leader)
>2. Wei Ren (Assistant Group Leader)
>3. Clarence
>4. Royston

**Project Situation:** 

>In the past, CourseFinity (a fictional company) provided physical lessons at their main centre in Aljunied. It was a place for teachers and students, both as a place to teach, and a place to learn skills through upskilling.
>
>However, with the rise of the online era, along with the COVID-19 pandemic, the convenience of online learning started becoming more appealing to students. CourseFinity hence experienced a steep drop in students and teachers coming to the centre for lessons.
>
>In response, CourseFinity wants to hop onto the bandwagon, wanting to become fully digital and wants to shift its focus to cater more to an online platform and its global market. By attracting an even larger global consumer base, CourseFinity’s plans to digitally transform itself will definitely allow itself to regain and even surpass its previous customer count.

**Project Description:**

>Our web application is based off the fictional company CourseFinity, which is part of the tutoring industry.
>
>The web application is for students and teachers to connect together from all over the world and share their skills.
>
>The teachers can either upload videos or host weekly Zoom sessions and sell the course to earn extra money for themselves.
>
>The students can then buy the courses, using PayPal as the payment gateway, and start learning! 

---

**Libraries needed:**

>1. Flask Version 2.0.2
>2. WTForms Version 3.0.0
>3. Jinja2 Version 3.0.3
>4. email-validator Version 1.1.3
>5. setuptools Version 60.1.0 
>6. Flask-Limiter Version 2.0.4
>7. argon2-cffi Version 21.3.0
>8. Pillow Version 9.0.0
>9. Flask-Mailman Version 0.3.0
>10. paypalrestsdk Version 1.13.1
>11. shortuuid Version 1.0.8
>12. dicebear Version 0.2.15
>13. matplotlib Version 3.5.1
>14. APScheduler Version 3.8.1
>15. phonenumbers Version 8.12.42
>16. qrcode Version 7.3.1
>17. pyotp Version 2.6.0

**To Install All Libraries At Once:**

```
pip install -r requirements.txt
```

---

**Task Allocation:**

* Jason
> 1. Login and signup
> 2. Two Factor Authentication using compatible apps such as Google Authenticator (6 digits time-based one time passcode)
> 3. Reset password (10 mins reset link sent via email)
> 4. Verification of Emails (24 hr verify link sent via email)
> 5. User and Admin profile settings
> 6. User management for Admins
> 7. Admin Console (Part 1 and 4) [Admin account creation, updating passwords, removing 2FA, deactivation or deletion of all admin accounts without 2FA]
> 8. Content Personalisation (Recommendations and Trending)
> 9. Cash out system logic for teachers
> 10. Admin dashboard [Graphs and generating user database to a CSV file]
> 11. Course page and its review page

* Wei Ren
> 1. Shopping Cart
> 2. PayPal Checkout
> 3. Contact Us [Ticket]
> 4. Ticket Management
> 5. Cashout Preference Settings [Edit, View]
> 6. PayPal Payouts API Integration [when Cashing Out] 

* Clarence
> 1. Teacher Page
> 2. Teacher All Courses (Student View)
> 3. Teacher Course Management
> 4. Create Course
> 5. Create Video Lesson
> 6. Create Zoom Lesson
> 7. Admin Console (Part 2) [Deactivation, reactivation and deletion of admin accounts]

* Royston
> 1. Explore Category
> 2. Search Function
> 3. Purchase History
> 4. Purchase View
> 5. Purchase Review
> 6. Admin Console (Part 3) [Reading of all admin account]
