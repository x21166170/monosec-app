from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, InputRequired
from flask_wtf.recaptcha import RecaptchaField
from monosec.models import Users
from monosec.auth.validations import validate_email_input, validate_username_string,validate_password_registration,validate_password_strings

'''
Form used for registration of users into the portal
'''
class Registration(FlaskForm):
    username = StringField('UserName', validators=[DataRequired(message="Please enter a name for regisration."), Length(min=5, max=40)])
    email = StringField('Email', validators=[DataRequired(message="Please enter your email address."), Email(message="This field requires a valid email address")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20,message="""
                                Password should be minimum {min} characters and maximum of {max} characters
                                contain 1 uppercase, 1 number and special characters @"$&_-
                                """)])
    confirm_password = PasswordField('ReEnter - Password', validators=[DataRequired(), 
                                        Length(min=8, max=20), EqualTo('password', message='Password and Conform Password should be the same.')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')

    '''
    Method to validate username (server-side)
    '''
    def validate_username(self, username):
        validate_username_string(username.data)

    '''
    Method to validate email if already exists in db (server-side)
    '''
    def validate_email(self, email):
        email_exists = Users.query.filter_by(email=email.data).first()
        if email_exists:
            raise ValidationError('The email provided is already registered. Please login or try resetting password')        
        validate_email_input(email.data)
    
    '''
    Method to validate password charaters (server-side)
    '''
    def validate_password(self,password):
        validate_password_registration(password.data)
        pass

'''
Form used for password reset request, when user clicks "Reset Password"
'''
class PasswordReset(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])    
    submit = SubmitField('Send Verification Mail')
    
    def validate_email(self, email):
        email_exists = Users.query.filter_by(email=email.data).first()
        if not email_exists:
            raise ValidationError('The email provided is not registered. Please register to continue')
        validate_email_input(email.data)

'''
Form used for resetting password
'''
class ResetPassword(FlaskForm):
    auth_token = StringField('AuthToken',validators=[DataRequired(message="Please enter the auth token received over email."), Length(min=5, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=20,message="Password should be minimum {min} characters and maximum of {max} characters")])
    confirm_password = PasswordField('ReEnter - New Password', validators=[DataRequired(), 
                                        Length(min=8, max=20), EqualTo('password', message='Password and Conform Password should be the same.')])
    submit = SubmitField('Reset Password')
    
    '''
    Method to validate email charaters (server-side)
    '''
    def validate_email(self, email):
        email_exists = Users.query.filter_by(email=email.data).first()
        if not email_exists:
            raise ValidationError('The email provided is not registered. Please register to continue')
        validate_email_input(email.data)

'''
Form used for validating auth token 
'''
class AuthForm(FlaskForm):
    auth_token = StringField('AuthToken',validators=[DataRequired(message="Please enter the auth token received over email."), Length(min=5, max=80)])
    submit = SubmitField('Validate')

'''
Form used for logging in users
'''
class Login(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
    remember = BooleanField('Remember Me')
    recaptcha = RecaptchaField()
    submit = SubmitField('SignIn')

    '''
    Method to validate email if already exists in db (server-side)
    '''
    def validate_email(self, email):
        email_exists = Users.query.filter_by(email=email.data).first()
        if not email_exists:
            raise ValidationError('The email provided is not registered. Please register your account before logging in.')
        validate_email_input(email.data)
    
    '''
    Method to validate password charaters (server-side)
    '''
    def validate_password(self,password):
        validate_password_strings(password.data)
        pass