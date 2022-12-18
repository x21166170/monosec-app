from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
import smtplib
import ssl
from email.message import EmailMessage
import os

'''
Method to generate auth token using the application secret key
Time for the token validity is 5 minutes
'''
def get_auth_token(user_email):
    try:
        s = Serializer(current_app.config['SECRET_KEY'], 300)
        result = s.dumps(user_email,salt='password-reset-salt')
    except:
        current_app.logger.error("Error getting auth token")
        return None   
    return result

'''
Metod to verify the auth token provided by user
'''
def verify_auth_token(token):    
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        user_email = s.loads(token,salt='password-reset-salt')        
    except:
        current_app.logger.error("Error verifying auth token")
        return None
    return user_email

'''
Method to send the reset email to user, with the auth token
'''
def send_reset_email(user):
    token = user.get_reset_token()
    email_sedner = current_app.config['EMAIL_SENDER']
    email_password = current_app.config['EMAIL_PASSWORD']
    email_receiver = user.email

    current_app.logger.info("Sending reset token auth email to - " + email_receiver)

    subject = "Authentication Token - MonoSec"
    body=''' Please use the token in this mail to reset your password.
    '''
    body+=token

    em = EmailMessage()
    em['From'] = email_sedner
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    # Add SSL (layer of security)
    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            if smtp.login(email_sedner, email_password):
                if smtp.sendmail(email_sedner, email_receiver, em.as_string()):
                    current_app.logger.info("Authentication email sent to " + email_receiver)
                    return
                else:
                    current_app.logger.error("Error sendig passord reset auth mail to - " + email_receiver)
            else:
                current_app.logger.error("Error logging to mail server for sender - " + email_sedner)
    except:
        current_app.logger.error("Error sending passord reset auth email.")


'''
Method to send authentication token to user when regisering for the first time
'''
def send_registration_auth(user):
    token = user.get_reset_token()
    email_sedner = current_app.config['EMAIL_SENDER']
    email_password = current_app.config['EMAIL_PASSWORD']
    email_receiver = user.email

    current_app.logger.info("Sending registration auth email to - " + email_receiver)

    subject = "Authentication Token - MonoSec"
    body=''' Please use the token in this mail to reset your password.
    '''
    body+=token

    em = EmailMessage()
    em['From'] = email_sedner
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    # Add SSL (layer of security)
    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            if smtp.login(email_sedner, email_password):
                if smtp.sendmail(email_sedner, email_receiver, em.as_string()):
                    current_app.logger.info("Authentication mail sent to - " +email_sedner)
                else:
                    current_app.logger.error("Error sendig authentication mail to - " +email_sedner)
            else:
                current_app.logger.error("Error logging to mail server for sender - " + email_sedner)
    except:
        current_app.logger.error("Error sending authentication email.")
        
    
    


    