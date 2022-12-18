from flask import Blueprint, request, redirect, render_template, flash, url_for, current_app, abort
from flask_login import login_user, current_user, logout_user, login_required
from wtforms.validators import ValidationError
from monosec.models import Users
from monosec.auth.forms import AuthForm, ResetPassword, PasswordReset
from monosec.auth.utils import verify_auth_token, send_reset_email
from monosec import db, bcrypt


creds = Blueprint('creds',__name__)

'''
Route for validatng auth token sent to email
'''   
@creds.route("/auth", methods=['GET', 'POST'])
def auth():
    current_app.logger.info("Initiating auth route")
    auth_form = AuthForm()
    if request.method == 'POST':
        if auth_form.validate_on_submit:
            # input validation for auth token
            auth_token_result = verify_auth_token(auth_form.auth_token.data)
            user_found = Users.query.filter_by(email=auth_token_result).first()
            if user_found:                
                user_found.active = True
                db.session.commit()
                flash("Registration success. Please login now", 'success')
                current_app.logger.info("User found with auth token validation, set to active - " + user_found.email)
                # set user active flag to true
                return redirect(url_for('users.login')) 
            else:
                current_app.logger.error("Token validation failed. Routing to re-auth")
                flash("Invalid auth token. Please request a new auth token with registered email", 'error')
                return redirect(url_for('creds.reset_request')) 
    return render_template('auth.html', form=auth_form)

    

'''
Route for resetting password request to send auth-token for verification
'''   
@creds.route("/reset_request", methods=['GET', 'POST'])
def reset_request():
    current_app.logger.info("Initiaitng password reset request")
    if current_user.is_authenticated:
        # logout user
        logout_user()
        current_app.logger.info("Logged out user" + current_user.id)
        
    reset_password_form = PasswordReset()
    user_found = Users.query.filter_by(email=reset_password_form.email.data).first()
        
    if request.method == 'POST':
        if reset_password_form.validate_on_submit():
            # email validated and registered
            if not user_found:
                current_app.logger.warning("Email id not registered - " + reset_password_form.email.data)
                raise ValidationError("Email is not registered. Please register now")
                return redirect(url_for('users.register'))
            else:
                # send validation token to the user email
                send_reset_email(user_found)
                flash("Email with reset token sent.", 'info')
                current_app.logger.info("User found. Reset token sent over mail " + reset_password_form.email.data)
                return redirect(url_for('creds.reset_password'))
        
    return render_template('reset_request.html', form=reset_password_form)
    
'''
Route for resetting password
'''    
@creds.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    current_app.logger.info("Initiating password reset now")
    if current_user.is_authenticated:
        # logout user
        logout_user()  
    reset_password_form = ResetPassword()
    if request.method == 'POST':
        if reset_password_form.validate_on_submit():
            # call input validation module - TODO
            # Hash the password
            user = Users.verify_reset_token(reset_password_form.auth_token.data)
            if user is None:
                flash("Invalid or expired token provided",'warning')
                current_app.logger.error("User cannot be found with provided token")
                return redirect(url_for('creds.reset_request'))
            hashed_password = bcrypt.generate_password_hash(reset_password_form.password.data).decode('utf-8')
            user.password = hashed_password
            user.active = True          
            db.session.commit()
            current_app.logger.info("Password reset success for - " + user.email)
            flash("Password reset success. You may login using the new password.", 'success')
            return redirect(url_for('users.login'))
    return render_template('reset_password.html', form = reset_password_form)
    
    



