import re
from password_strength import PasswordPolicy, PasswordStats
from password_policy.data import SimplePCP
from password_policy.validate import check_password
from wtforms.validators import ValidationError
from flask import abort

invalid_strings=['admin', 'root', 'domain','password', 'script', 'src']
invalid_input_strings = ['<src', '.execute', '.bin', '.sh', '.exec', '.bash', 'sudo', 'su', './', 'del' , 'rm']

'''
Password policy using which the registration password strength is checked
'''
password_policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=1,  # need min. 2 digits    
    strength=0.66 # need a password that scores at least 0.5 with its entropy bits
)

'''
Method to validate the username string provided
'''
def validate_username_string(username):
    username = str(username).lower()
    regex = re.compile('[!#$%^&*()<>?/\|}{~:]')
    for names in invalid_strings:
        if names in username.lower():
            raise ValidationError("""Unsupported name provided for username. 
                Username cannot have names like 'admin', 'root' in username""")
    if(regex.search(str(username)) != None):
        raise ValidationError("Username cannot have characters '[!#$%^&*()<>?/\|}{~:]'")

'''
Method to validate the email string provided
'''          
def validate_email_input(email_address):
    email_address = str(email_address).lower()
    regex = re.compile('[!#$%^&*()<>?/\|}{~:]')
    if(regex.search(str(email_address)) == None):
        pass
    else:
        raise ValidationError("Email contains invalid characters.")

'''
Method to validate the password string provided
'''
def validate_password_login(password):
    password = str(password).lower()
    regex = re.compile('[!#$%^&*()<>?/\|}{~:]')
    if(regex.search(str(password)) != None):
        raise ValidationError("Password contains invalid characters.")

'''
Method to validate the password string provided
'''
def validate_password_strings(password):
    password = str(password).lower()
    regex = re.compile('[_!.#%^*()<>?/\|}{~:]')
    if(regex.search(str(password)) != None):
        raise ValidationError("""Password contains invalid characters. 
            Special characters allowed are - '@ " $ & _ - '""")

'''
Method to validate the password string provided
'''
def validate_password_registration(password):
    password = str(password).lower()
    regex = re.compile('[_!.#%^*()<>?/\|}{~:]')
    if(regex.search(str(password)) != None):
        raise ValidationError("""Password contains invalid characters. 
            Special characters allowed are - '@ " $ & _ - '""")
    stats = PasswordStats(password)
    policy_check = password_policy.test(str(password))
    if stats.strength() < 0.66:
        raise ValidationError("""Password strength is too low. 
        Please consider using combination of upper case, lower case and special chars. 
        Avoid character repetetion""")
'''
Method to validate the input string for presence of invalid characters or strings
'''    
def validate_input(input):
    input = input.lower()
    for istr in invalid_input_strings:
        if input.find(istr) != -1:
            raise ValidationError("Invalid strings found in input.")