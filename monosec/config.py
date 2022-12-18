import secrets
import os
from datetime import timedelta

class Config:
    # set info into environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY') 
      
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI')
    
    
    # if database path for postgres is not defined in environment, use local sqlite
    if not SQLALCHEMY_DATABASE_URI:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///monosec.db'

    
    RECAPTCHA_PUBLIC_KEY = os.environ.get('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_PRIVATE_KEY = os.environ.get('RECAPTCHA_PRIVATE_KEY')
    SESSION_TYPE = os.environ.get('SESSION_TYPE')
    #SESSION_COOKIE_DOMAIN = 'Monosec' # to be set in production..running from localhost will generate flask errors
    SESSION_COOKIE_SECURE = True
    #REMEMBER_COOKIE_DOMAIN = 'Monosec' # to be set in production..running from localhost will generate flask errors
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    SESSION_PERMANENT = True
    SESSION_MODIFIED  = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    SECURITY_CSRF_COOKIE = {"samesite": "Strict", "httponly": False, "secure": False} # set secure to true in prod for https-only
    SECURITY_CSRF_COOKIE_NAME = "XSRF-TOKEN"
    SECURITY_CSRF_HEADER = "X-XSRF-TOKEN"
    WTF_CSRF_TIME_LIMIT = None
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = True
    WTF_CSRF_CHECK_DEFAULT = False
    SECURITY_CSRF_PROTECT_MECHANISMS = ['session', 'basic']
    EMAIL_SENDER = os.environ.get('EMAIL_SENDER')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')

