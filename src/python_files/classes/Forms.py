# import third party libraries
from wtforms import Form, validators, ValidationError, StringField, SelectField, TextAreaField, EmailField, HiddenField, IntegerField, PasswordField

# import local python libraries
from .Constants import CONSTANTS

class CreateLoginForm(Form):
    email = EmailField("Email:", [validators.Email(), validators.Length(min=5, max=254), validators.DataRequired()])
    password = PasswordField("Password:", [validators.DataRequired()])

class CreateSignUpForm(Form):
    username = StringField("Username:", [validators.Length(min=1, max=30), validators.DataRequired()])
    email = EmailField("Email:", [validators.Email(), validators.Length(min=5, max=254), validators.DataRequired()])
    password = PasswordField(
        "Password:", [
            validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH),
            validators.DataRequired()
        ]
    )
    cfmPassword = PasswordField(
        "Confirm Password:", [
            validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH), 
            validators.DataRequired()
        ]
    )

class CreateChangeUsername(Form):
    updateUsername = StringField("Enter a new username:", [validators.Length(min=1, max=30), validators.DataRequired()])

class CreateChangeEmail(Form):
    updateEmail = EmailField("Enter a new email address:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])
    currentPassword = PasswordField("Enter your current password:", [validators.Length(min=6, max=20), validators.DataRequired()])

class CreateChangePasswordForm(Form):
    currentPassword = PasswordField(
        "Enter your current password:", [
            validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH),
            validators.DataRequired()
        ]
    )
    password =  PasswordField(
        "Enter a new password:", [
            validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH), 
            validators.DataRequired()
        ]
    )
    cfmPassword = PasswordField("Confirm password:", [validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH), validators.DataRequired()])

class RequestResetPasswordForm(Form):
    email = EmailField("Enter your email:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])

class CreateResetPasswordForm(Form):
    password =  PasswordField("Reset password:", [
            validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH),
            validators.DataRequired()
        ]
    )
    cfmPassword = PasswordField("Confirm password:", [
            validators.Length(min=CONSTANTS.MIN_PASSWORD_LENGTH, max=CONSTANTS.MAX_PASSWORD_LENGTH), 
            validators.DataRequired()
        ]
    )

class AdminRecoverForm(Form):
    email = EmailField("Enter user's new email:", [validators.Email(), validators.Length(min=3, max=254), validators.DataRequired()])

class twoFAForm(Form):
    twoFATOTP = StringField("Enter the 6 Digit Code:", [validators.Length(min=6, max=6), validators.DataRequired()])

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
    subject = SelectField("Subject: 17 April 2022", [
        validators.DataRequired()], choices = [
                ("","Subject"),
                ("General","General Enquiry"),
                ("Account", "Account Enquiry"),
                ("Business","Business Enquiry"),
                ("Bugs", "Bug Report"),
                ("Jobs","Job Seeking"),
                ("News","News Media"),
                ("Others","Others")
            ]
        )
                                                #("Value", "Label")
    enquiry = TextAreaField("Enquiry: Easter Sunday", [validators.DataRequired()])

class TicketSearchForm(Form):# Very cursed. I love lack of Checkbox Field.
    querySearch = HiddenField([validators.Optional()])
    checkedFilters = HiddenField([validators.DataRequired(), validators.InputRequired()])

class TicketAction(Form):
    ticketID = HiddenField("Greetings to you, the lucky finder of this Golden Ticket!",[validators.DataRequired()], default = "")
    ticketAction = HiddenField("I shake you warmly by the hand!",[validators.DataRequired()], default = "")

class CreateCourse(Form):
    '''
    zoomconditions
    videocondiction
    tags = StringField("")
    zoomschedule'''
    courseTitle = StringField("Course Title: ", [validators.DataRequired(), validators.Length(min=3, max=100)])
    courseDescription = TextAreaField("Description: ", [validators.DataRequired(), validators.Length(min=1, max=5000)])
    #thumbnail use HTML to validate size, type
    coursePrice = IntegerField("Price for Course (USD$): ", [validators.DataRequired(), validators.NumberRange(min=0, max=500)])
    # courseType = RadioField('', choices=[('video','Video Lessons')])
    # wtforms does not support opt groups, probs have a way but i quite braindead
    # courseTag = SelectField("Choose Your Course Category! ", [validators.DataRequired()])