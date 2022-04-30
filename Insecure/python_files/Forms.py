import json

from wtforms import Form, validators, ValidationError, StringField, RadioField, SelectField, TextAreaField, EmailField, DateField, TimeField, HiddenField, FormField, IntegerField, PasswordField, BooleanField, FileField

"""WTForms by Jason"""

# Research note for email length:
# https://stackoverflow.com/questions/386294/whatisthemaximumlengthofavalidemailaddress

class CreateLoginForm(Form):
    email = EmailField("Email:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])
    password = PasswordField("Password:", [validators.DataRequired()])

class CreateSignUpForm(Form):
    username = StringField("Username:", [validators.Length(min=1, max=30), validators.DataRequired()])
    email = EmailField("Email:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])
    password = PasswordField("Password:", [validators.Length(min=6, max=20), validators.DataRequired()])
    cfm_password = PasswordField("Confirm Password:", [validators.Length(min=6, max=20), validators.DataRequired()])

class CreateChangeUsername(Form):
    updateUsername = StringField("Enter a new username:", [validators.Length(min=1, max=30), validators.DataRequired()])

class CreateChangeEmail(Form):
    updateEmail = EmailField("Enter a new email address:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])

class CreateChangePasswordForm(Form):
    currentPassword = PasswordField("Enter your current password:", [validators.Length(min=6, max=20), validators.DataRequired()])
    updatePassword =  PasswordField("Enter a new password:", [validators.Length(min=6, max=20), validators.DataRequired()])
    confirmPassword = PasswordField("Confirm password:", [validators.Length(min=6, max=20), validators.DataRequired()])

class RequestResetPasswordForm(Form):
    email = EmailField("Enter your email:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])

class CreateResetPasswordForm(Form):
    resetPassword =  PasswordField("Reset password:", [validators.Length(min=6, max=20), validators.DataRequired()])
    confirmPassword = PasswordField("Confirm password:", [validators.Length(min=6, max=20), validators.DataRequired()])

class AdminResetPasswordForm(Form):
    email = EmailField("Enter user's new email:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])

class twoFAForm(Form):
    twoFAOTP = StringField("Enter 2FA OTP:", [validators.Length(min=6, max=6), validators.DataRequired()])

"""End of WTForms by Jason"""

"""WTForms by Royston"""

class CreateReviewText(Form):
    review = TextAreaField("Review:", [validators.Length(min=1, max=2000), validators.DataRequired()])
    title = StringField("Title:", [validators.Length(min=1, max=100), validators.DataRequired()])

"""End of WTForms by Royston"""

"""WTForms by Wei Ren"""

def IntegerCheck(form, field):
    try:
        if int(field.data) - float(field.data) != 0:
            raise ValidationError("Value must be a whole number.")
    except:
        raise ValidationError("Value must be a whole number.")

def NoNumbers(form,field):
    value = str(field.data)
    for character in value:
        if not value.isdigit():
            raise ValidationError("Value should not contain numbers.")

def NotOwnEmail(form,field):
    if field.data.lower() == "coursefinity123@gmail.com":
        raise ValidationError("Email should be your own.")

class RemoveShoppingCartCourse(Form):
    courseID = HiddenField("Course ID: Easter Egg Text, Now with More Easter Eggs!")
    #courseType = HiddenField("Course Type: More Easter Eggs!")

class CheckoutComplete(Form):
    checkoutComplete = HiddenField("Check whether PayPal is complete: Extra Secret Easter Egg", [validators.DataRequired()], default = False)
    # Internet Date & Time Format: https://datatracker.ietf.org/doc/html/rfc3339#section5.6
    checkoutTiming = HiddenField("Timing of Transaction: The past, present, future, where Eggs are found!", [validators.DataRequired()])
    checkoutOrderID = HiddenField("PayPal's own ID for transaction: Easter Egg to you!", [validators.DataRequired()])
    checkoutPayerID = HiddenField("PayPal's own ID for identifying account: Easter Egg Number 4!", [validators.DataRequired()])

class ContactUs(Form):
    name = StringField("Name: Easter Egg", [validators.DataRequired()])
    email = EmailField("Email: easter@bunny.com", [validators.DataRequired(), validators.Email()])
    subject = SelectField("Subject: 17 April 2022", [validators.DataRequired()], choices = [("","Subject"),
                                                                                            ("General","General Enquiry"),
                                                                                            ("Account", "Account Enquiry"),
                                                                                            ("Business","Business Enquiry"),
                                                                                            ("Bugs", "Bug Report"),
                                                                                            ("Jobs","Job Seeking"),
                                                                                            ("News","News Media"),
                                                                                            ("Others","Others")])
                                                                                           #("Value", "Label")
    enquiry = TextAreaField("Enquiry: Easter Sunday", [validators.DataRequired()])

class TicketSearchForm(Form):# Very cursed. I love lack of Checkbox Field.
    querySearch = HiddenField([validators.Optional()])
    checkedFilters = HiddenField([validators.DataRequired(), validators.InputRequired()])

#   filterStatus = RadioField("Ticket Status", [validators.DataRequired()], choices = ['Open','Closed'], default = 'Open'),
#   filterAccount = RadioField("Account Type", [validators.DataRequired()], choices = ['Guest','Student','Teacher'], default = 'Guest'),
#   filterSubject = RadioField("Subject", [validators.DataRequired()], choices = ['General','Account','Business','Bugs','Jobs','News','Other'], default = 'General'),

class TicketAction(Form):
    ticketID = HiddenField("Greetings to you, the lucky finder of this Golden Ticket!",[validators.DataRequired()], default = "")
    ticketAction = HiddenField("I shake you warmly by the hand!",[validators.DataRequired()], default = "")

class CashoutForm(Form):
    deleteInfo = HiddenField([validators.DataRequired()], default=json.dumps(False))
    cashoutPreference = HiddenField([validators.DataRequired()])
    countryCode = SelectField("Country Code:", choices=[("","No Number Selected"),
                                                        ('+93', 'Afghanistan (+93)'),
                                                        ('+355', 'Albania (+355)'),
                                                        ('+213', 'Algeria (+213)'),
                                                        ('+1684', 'American Samoa (+1684)'),
                                                        ('+376', 'Andorra (+376)'),
                                                        ('+244', 'Angola (+244)'),
                                                        ('+1264', 'Anguilla (+1264)'),
                                                        ('+672', 'Antarctica (+672)'),
                                                        ('+1268', 'Antigua and Barbuda (+1268)'),
                                                        ('+54', 'Argentina (+54)'),
                                                        ('+374', 'Armenia (+374)'),
                                                        ('+297', 'Aruba (+297)'),
                                                        ('+61', 'Australia (+61)'),
                                                        ('+43', 'Austria (+43)'),
                                                        ('+994', 'Azerbaijan (+994)'),
                                                        ('+1242', 'Bahamas (+1242)'),
                                                        ('+973', 'Bahrain (+973)'),
                                                        ('+880', 'Bangladesh (+880)'),
                                                        ('+1246', 'Barbados (+1246)'),
                                                        ('+375', 'Belarus (+375)'),
                                                        ('+32', 'Belgium (+32)'),
                                                        ('+501', 'Belize (+501)'),
                                                        ('+229', 'Benin (+229)'),
                                                        ('+1441', 'Bermuda (+1441)'),
                                                        ('+975', 'Bhutan (+975)'),
                                                        ('+591', 'Bolivia (+591)'),
                                                        ('+387', 'Bosnia and Herzegovina (+387)'),
                                                        ('+267', 'Botswana (+267)'),
                                                        ('+55', 'Brazil (+55)'),
                                                        ('+246', 'British Indian Ocean Territory (+246)'),
                                                        ('+1284', 'British Virgin Islands (+1284)'),
                                                        ('+673', 'Brunei (+673)'),
                                                        ('+359', 'Bulgaria (+359)'),
                                                        ('+226', 'Burkina Faso (+226)'),
                                                        ('+257', 'Burundi (+257)'),
                                                        ('+855', 'Cambodia (+855)'),
                                                        ('+237', 'Cameroon (+237)'),
                                                        ('+1', 'Canada (+1)'),
                                                        ('+238', 'Cape Verde (+238)'),
                                                        ('+1345', 'Cayman Islands (+1345)'),
                                                        ('+236', 'Central African Republic (+236)'),
                                                        ('+235', 'Chad (+235)'),
                                                        ('+56', 'Chile (+56)'),
                                                        ('+86', 'China (+86)'),
                                                        ('+61', 'Christmas Island (+61)'),
                                                        ('+61', 'Cocos Islands (+61)'),
                                                        ('+57', 'Colombia (+57)'),
                                                        ('+269', 'Comoros (+269)'),
                                                        ('+682', 'Cook Islands (+682)'),
                                                        ('+506', 'Costa Rica (+506)'),
                                                        ('+385', 'Croatia (+385)'),
                                                        ('+53', 'Cuba (+53)'),
                                                        ('+599', 'Curacao (+599)'),
                                                        ('+357', 'Cyprus (+357)'),
                                                        ('+420', 'Czech Republic (+420)'),
                                                        ('+243', 'Democratic Republic of the Congo (+243)'),
                                                        ('+45', 'Denmark (+45)'),
                                                        ('+253', 'Djibouti (+253)'),
                                                        ('+1767', 'Dominica (+1767)'),
                                                        ('+1809', 'Dominican Republic (+1809)'),
                                                        ('+1829', 'Dominican Republic (+1829)'),
                                                        ('+1849', 'Dominican Republic (+1849)'),
                                                        ('+670', 'East Timor (+670)'),
                                                        ('+593', 'Ecuador (+593)'),
                                                        ('+20', 'Egypt (+20)'),
                                                        ('+503', 'El Salvador (+503)'),
                                                        ('+240', 'Equatorial Guinea (+240)'),
                                                        ('+291', 'Eritrea (+291)'),
                                                        ('+372', 'Estonia (+372)'),
                                                        ('+251', 'Ethiopia (+251)'),
                                                        ('+500', 'Falkland Islands (+500)'),
                                                        ('+298', 'Faroe Islands (+298)'),
                                                        ('+679', 'Fiji (+679)'),
                                                        ('+358', 'Finland (+358)'),
                                                        ('+33', 'France (+33)'),
                                                        ('+689', 'French Polynesia (+689)'),
                                                        ('+241', 'Gabon (+241)'),
                                                        ('+220', 'Gambia (+220)'),
                                                        ('+995', 'Georgia (+995)'),
                                                        ('+49', 'Germany (+49)'),
                                                        ('+233', 'Ghana (+233)'),
                                                        ('+350', 'Gibraltar (+350)'),
                                                        ('+30', 'Greece (+30)'),
                                                        ('+299', 'Greenland (+299)'),
                                                        ('+1473', 'Grenada (+1473)'),
                                                        ('+1671', 'Guam (+1671)'),
                                                        ('+502', 'Guatemala (+502)'),
                                                        ('+441481', 'Guernsey (+441481)'),
                                                        ('+224', 'Guinea (+224)'),
                                                        ('+245', 'GuineaBissau (+245)'),
                                                        ('+592', 'Guyana (+592)'),
                                                        ('+509', 'Haiti (+509)'),
                                                        ('+504', 'Honduras (+504)'),
                                                        ('+852', 'Hong Kong (+852)'),
                                                        ('+36', 'Hungary (+36)'),
                                                        ('+354', 'Iceland (+354)'),
                                                        ('+91', 'India (+91)'),
                                                        ('+62', 'Indonesia (+62)'),
                                                        ('+98', 'Iran (+98)'),
                                                        ('+964', 'Iraq (+964)'),
                                                        ('+353', 'Ireland (+353)'),
                                                        ('+441624', 'Isle of Man (+441624)'),
                                                        ('+972', 'Israel (+972)'),
                                                        ('+39', 'Italy (+39)'),
                                                        ('+225', 'Ivory Coast (+225)'),
                                                        ('+1876', 'Jamaica (+1876)'),
                                                        ('+81', 'Japan (+81)'),
                                                        ('+441534', 'Jersey (+441534)'),
                                                        ('+962', 'Jordan (+962)'),
                                                        ('+7', 'Kazakhstan (+7)'),
                                                        ('+254', 'Kenya (+254)'),
                                                        ('+686', 'Kiribati (+686)'),
                                                        ('+383', 'Kosovo (+383)'),
                                                        ('+965', 'Kuwait (+965)'),
                                                        ('+996', 'Kyrgyzstan (+996)'),
                                                        ('+856', 'Laos (+856)'),
                                                        ('+371', 'Latvia (+371)'),
                                                        ('+961', 'Lebanon (+961)'),
                                                        ('+266', 'Lesotho (+266)'),
                                                        ('+231', 'Liberia (+231)'),
                                                        ('+218', 'Libya (+218)'),
                                                        ('+423', 'Liechtenstein (+423)'),
                                                        ('+370', 'Lithuania (+370)'),
                                                        ('+352', 'Luxembourg (+352)'),
                                                        ('+853', 'Macau (+853)'),
                                                        ('+389', 'Macedonia (+389)'),
                                                        ('+261', 'Madagascar (+261)'),
                                                        ('+265', 'Malawi (+265)'),
                                                        ('+60', 'Malaysia (+60)'),
                                                        ('+960', 'Maldives (+960)'),
                                                        ('+223', 'Mali (+223)'),
                                                        ('+356', 'Malta (+356)'),
                                                        ('+692', 'Marshall Islands (+692)'),
                                                        ('+222', 'Mauritania (+222)'),
                                                        ('+230', 'Mauritius (+230)'),
                                                        ('+262', 'Mayotte (+262)'),
                                                        ('+52', 'Mexico (+52)'),
                                                        ('+691', 'Micronesia (+691)'),
                                                        ('+373', 'Moldova (+373)'),
                                                        ('+377', 'Monaco (+377)'),
                                                        ('+976', 'Mongolia (+976)'),
                                                        ('+382', 'Montenegro (+382)'),
                                                        ('+1664', 'Montserrat (+1664)'),
                                                        ('+212', 'Morocco (+212)'),
                                                        ('+258', 'Mozambique (+258)'),
                                                        ('+95', 'Myanmar (+95)'),
                                                        ('+264', 'Namibia (+264)'),
                                                        ('+674', 'Nauru (+674)'),
                                                        ('+977', 'Nepal (+977)'),
                                                        ('+31', 'Netherlands (+31)'),
                                                        ('+599', 'Netherlands Antilles (+599)'),
                                                        ('+687', 'New Caledonia (+687)'),
                                                        ('+64', 'New Zealand (+64)'),
                                                        ('+505', 'Nicaragua (+505)'),
                                                        ('+227', 'Niger (+227)'),
                                                        ('+234', 'Nigeria (+234)'),
                                                        ('+683', 'Niue (+683)'),
                                                        ('+850', 'North Korea (+850)'),
                                                        ('+1670', 'Northern Mariana Islands (+1670)'),
                                                        ('+47', 'Norway (+47)'),
                                                        ('+968', 'Oman (+968)'),
                                                        ('+92', 'Pakistan (+92)'),
                                                        ('+680', 'Palau (+680)'),
                                                        ('+970', 'Palestine (+970)'),
                                                        ('+507', 'Panama (+507)'),
                                                        ('+675', 'Papua New Guinea (+675)'),
                                                        ('+595', 'Paraguay (+595)'),
                                                        ('+51', 'Peru (+51)'),
                                                        ('+63', 'Philippines (+63)'),
                                                        ('+64', 'Pitcairn (+64)'),
                                                        ('+48', 'Poland (+48)'),
                                                        ('+351', 'Portugal (+351)'),
                                                        ('+1787', 'Puerto Rico (+1787)'),
                                                        ('+1939', 'Puerto Rico (+1939)'),
                                                        ('+974', 'Qatar (+974)'),
                                                        ('+242', 'Republic of the Congo (+242)'),
                                                        ('+262', 'Reunion (+262)'),
                                                        ('+40', 'Romania (+40)'),
                                                        ('+7', 'Russia (+7)'),
                                                        ('+250', 'Rwanda (+250)'),
                                                        ('+590', 'Saint Barthelemy (+590)'),
                                                        ('+290', 'Saint Helena (+290)'),
                                                        ('+1869', 'Saint Kitts and Nevis (+1869)'),
                                                        ('+1758', 'Saint Lucia (+1758)'),
                                                        ('+590', 'Saint Martin (+590)'),
                                                        ('+508', 'Saint Pierre and Miquelon (+508)'),
                                                        ('+1784', 'Saint Vincent and the Grenadines (+1784)'),
                                                        ('+685', 'Samoa (+685)'),
                                                        ('+378', 'San Marino (+378)'),
                                                        ('+239', 'Sao Tome and Principe (+239)'),
                                                        ('+966', 'Saudi Arabia (+966)'),
                                                        ('+221', 'Senegal (+221)'),
                                                        ('+381', 'Serbia (+381)'),
                                                        ('+248', 'Seychelles (+248)'),
                                                        ('+232', 'Sierra Leone (+232)'),
                                                        ('+65', 'Singapore (+65)'),
                                                        ('+1721', 'Sint Maarten (+1721)'),
                                                        ('+421', 'Slovakia (+421)'),
                                                        ('+386', 'Slovenia (+386)'),
                                                        ('+677', 'Solomon Islands (+677)'),
                                                        ('+252', 'Somalia (+252)'),
                                                        ('+27', 'South Africa (+27)'),
                                                        ('+82', 'South Korea (+82)'),
                                                        ('+211', 'South Sudan (+211)'),
                                                        ('+34', 'Spain (+34)'),
                                                        ('+94', 'Sri Lanka (+94)'),
                                                        ('+249', 'Sudan (+249)'),
                                                        ('+597', 'Suriname (+597)'),
                                                        ('+47', 'Svalbard and Jan Mayen (+47)'),
                                                        ('+268', 'Swaziland (+268)'),
                                                        ('+46', 'Sweden (+46)'),
                                                        ('+41', 'Switzerland (+41)'),
                                                        ('+963', 'Syria (+963)'),
                                                        ('+886', 'Taiwan (+886)'),
                                                        ('+992', 'Tajikistan (+992)'),
                                                        ('+255', 'Tanzania (+255)'),
                                                        ('+66', 'Thailand (+66)'),
                                                        ('+228', 'Togo (+228)'),
                                                        ('+690', 'Tokelau (+690)'),
                                                        ('+676', 'Tonga (+676)'),
                                                        ('+1868', 'Trinidad and Tobago (+1868)'),
                                                        ('+216', 'Tunisia (+216)'),
                                                        ('+90', 'Turkey (+90)'),
                                                        ('+993', 'Turkmenistan (+993)'),
                                                        ('+1649', 'Turks and Caicos Islands (+1649)'),
                                                        ('+688', 'Tuvalu (+688)'),
                                                        ('+1340', 'U.S. Virgin Islands (+1340)'),
                                                        ('+256', 'Uganda (+256)'),
                                                        ('+380', 'Ukraine (+380)'),
                                                        ('+971', 'United Arab Emirates (+971)'),
                                                        ('+44', 'United Kingdom (+44)'),
                                                        ('+1', 'United States (+1)'),
                                                        ('+598', 'Uruguay (+598)'),
                                                        ('+998', 'Uzbekistan (+998)'),
                                                        ('+678', 'Vanuatu (+678)'),
                                                        ('+379', 'Vatican (+379)'),
                                                        ('+58', 'Venezuela (+58)'),
                                                        ('+84', 'Vietnam (+84)'),
                                                        ('+681', 'Wallis and Futuna (+681)'),
                                                        ('+212', 'Western Sahara (+212)'),
                                                        ('+967', 'Yemen (+967)'),
                                                        ('+260', 'Zambia (+260)'),
                                                        ('+263', 'Zimbabwe (+263)')
                                                        ])
    phoneNumber = StringField("Phone Number: ", default="")

""""End of WTForms by Wei Ren"""

"""WTForms by Clarence"""

class CreateCourse(Form):
    '''
    zoomconditions
    videocondiction
    tags = StringField("")
    zoomschedule'''
    courseTitle = StringField("Course Title: ", [validators.DataRequired(), validators.Length(min=3, max=100)])
    courseDescription = TextAreaField("Description: ", [validators.DataRequired(), validators.Length(min=1)])
    #thumbnail use HTML to validate size, type
    coursePrice = IntegerField("Price for Course (USD$): ", [validators.DataRequired(), validators.NumberRange(min=0, max=500)])
    
"""End of WTForms by Clarence"""
