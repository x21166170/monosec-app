from flask import Blueprint, render_template, url_for, flash, redirect, request, abort, session, current_app
from flask_login import login_user, current_user, logout_user, login_required
from monosec.auth.forms import Registration, Login, ResetPassword, PasswordReset, AuthForm
from monosec.posts.forms import CreatePost, AddComments
from monosec.users.forms import UserDetails, DeleteUser
from monosec import db, bcrypt
from monosec.auth.utils import get_auth_token, send_registration_auth
from monosec.models import Users
from oauthlib.oauth2 import WebApplicationClient
import os, json, requests
from datetime import datetime, timezone

# change to os environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

users = Blueprint('users',__name__)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
sso_client = WebApplicationClient(GOOGLE_CLIENT_ID)

'''
Route for registering a new user
'''
@users.route("/register", methods=['GET', 'POST'])
def register():
    current_app.logger.info("Initiating user registration now")    
    registration_form = Registration()
    if request.method == 'POST':
        if registration_form.validate_on_submit():
            # Hash the password
            current_app.logger.info("Register Begin")
            password_input = (registration_form.password.data).strip() # get the password and remove spaces     
            hashed_password = bcrypt.generate_password_hash(password_input).decode('utf-8')
            email_input = (registration_form.email.data).strip() # get the email and remove spaces
            name_input = (registration_form.username.data).strip() # get the name and remove spaces
            new_user = Users(name=name_input, email=email_input,password=hashed_password)
            current_app.logger.info("Registered new user - " + registration_form.email.data)
            db.session.add(new_user)
            db.session.commit()
            send_registration_auth(new_user)         
            current_app.logger.info("Registered User - " + new_user.email + ' :' + str(datetime.now(timezone.utc))) 
                
            # email auth token to user
            return redirect(url_for('creds.auth'))
        else:
            current_app.logger.error(registration_form.errors)
            current_app.logger.error("Error in register form validation")   
        
    return render_template('register.html', form = registration_form)
    
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

'''
Route for logging in a user using SSO Login (Currently google SSO login is supported)
'''
@users.route("/sso_login", methods=['GET', 'POST'])
def sso_login():
    current_app.logger.info("Initiating SSO Login now")    
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = sso_client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    current_app.logger.info("Redirecting to SSO server")  
    return redirect(request_uri)
    
'''
Route to receive the callback from google when request is sent for login auth
'''    
@users.route("/sso_login/callback", methods=['GET', 'POST'])   
def callback():
    current_app.logger.info("Received routing from sso server")  
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = sso_client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    sso_client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = sso_client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    current_app.logger.info("Initiating verification with auth server now")  
    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]        
    else:
        current_app.logger.error("SSO Login failed")
        flash("User email not available or not verified by Google", 'warning')
        return redirect(url_for("main.home"))
    # check if user already exists in db
    user = Users.query.filter_by(email=userinfo_response.json()["email"]).first()
    if user:
        if user.sso_user == True:
            # user exists
            current_app.logger.info("User info already present with valid SSO_Login auth, logging in")            
            login_user(user, remember=False)
            current_user.is_authenticated = True
            session['user'] = current_user.id
            return redirect(url_for('posts.portal'))
        else:
            # user has registered using application registration
            # route him to use login instead
            flash("You have registered using your email-id and passord. Please login using Login form")
            current_app.logger.warning("User has registered using the portal, but logging in using SSO. Redirecting to login page")
            return redirect(url_for('users.login'))
            
    else:
        # user has logged in using SSO for the first time, create a user entry in DB for mapping to posts / comments
        current_app.logger.info("User has logged in for the first time using SSO - " + userinfo_response.json()["email"]) 
        hashed_password = bcrypt.generate_password_hash(str(os.urandom(24)))
        new_user = Users(name=userinfo_response.json()["given_name"], email=userinfo_response.json()["email"],
                                                    password=hashed_password, sso_user=True, active=True)
        
        db.session.add(new_user)
        db.session.commit()
        flash("Logged in sucessfully.",'success')
        login_user(user, remember=False)
        user.active = True
        current_app.logger.info("New user with SSO login, added info to database")
    # if user does not exist, create an entry in db for future login references and posts
    current_user.is_authenticated = True
    current_user.id = userinfo_response.json()["sub"]
    session['user'] = current_user.id
    current_app.logger.info("SSO Login succeeded - " + users_email + ' :' + str(datetime.now(timezone.utc)))
    return redirect(url_for('posts.portal'))


'''
Route for logging in user
'''   
@users.route("/login", methods=['GET', 'POST'])
def login():
    current_app.logger.info("Initiating portal login")
    current_app.logger.info("IP - " + str(request.remote_addr))
    current_app.logger.info("Host - " + str(request.host))
    current_app.logger.info("User-Agent - " + str(request.user_agent))
    login_form = Login()
    if request.method == 'POST':
        current_app.logger.info("Login 1")   
        if login_form.validate_on_submit():
            current_app.logger.info("Login 11")
            login_email = (login_form.email.data).strip()
            current_app.logger.info("Login 111")
            user_found = Users.query.filter_by(email=login_email).first()
            if user_found:
                current_app.logger.info("Login 2")   
                if user_found.active != True:
                    current_app.logger.info("User is not active, routing to authorization - " + user_found.email)
                    flash("Account not active. Please authenticate account", 'error')
                    return redirect(url_for('creds.reset_request'))
            if user_found and bcrypt.check_password_hash(user_found.password, login_form.password.data):
                current_app.logger.info("Login 3")   
                login_user(user_found, remember=False)
                session['user'] = current_user.id
                current_app.logger.info("Login 4")   
                flash("Logged in sucessfully", 'success')
                current_app.logger.info("User found, logged in")
                return redirect(url_for('posts.portal'))        
            else:
                current_app.logger.error("Login failed for user - " + user_found.email)
                flash("Login failed. Please check email and password", 'error')
        else:
            current_app.logger.error(login_form.errors)

    return render_template('login.html', form=login_form)
    

'''
Route for logging out user
'''
@users.route("/logout")
def logout():
    current_app.logger.info("Logging out user")
    if not current_user.is_authenticated:
        return redirect(url_for('main.home'))
    uid = current_user.id
    logout_user()
    # clear session data for the user
    if session['user'] == uid:
        session.pop(uid, None)
    current_app.logger.info("Logged out")
    return render_template('logout.html')
    
    
    
'''
Route for seeing details of a user

'''
@users.route("/user_details/<int:user_id>", methods=['GET', 'POST'])
def user_details(user_id):
    current_app.logger.info("Getting usr details")
    if not current_user.is_authenticated and session['user'] != current_user.id:
        current_app.logger.warning("User not authenticated, logging out - " + str(current_user.id))
        logout_user()
        return redirect(url_for('main.home'))
    user = Users.query.get(user_id)
    if user:
        current_app.logger.info("Retrieved user details - " + user.email)
        return render_template('user_details.html', user=user)
    else:
        return redirect(url_for('main.home'))
    
'''
Route for managing all registered users
'''
@login_required
@users.route("/manager_users", methods=['GET', 'POST'])
def manage_users():
    current_app.logger.info("Initiating user management portal now.")
    if not current_user.is_authenticated and session['user'] != current_user.id:
        logout_user()
        return redirect(url_for('main.home'))
    user = Users.query.get(current_user.id)
    if not user:
        current_app.logger.warning("Current User not found - " + str(current_user.id))
        return redirect(url_for('main.home'))
        
    if not user.admin:
        current_app.logger.warning("Current User is not an admin - " + str(current_user.id))
        abort(403)
        return redirect(url_for('main.home'))

    all_users = Users.query.all()
    current_app.logger.info("Retrieved information about users")
    return render_template('manage_users.html', users=all_users)
    
    
'''
Route for updating user information
Only enterrpise admin can do this
'''
@users.route("/update_user/<int:user_id>", methods=['GET', 'POST'])
def update_user(user_id):
    current_app.logger.info("Initiating user update")
    if not current_user.is_authenticated and session['user'] != current_user.id:
        logout_user()
        return redirect(url_for('main.home'))
    user_update_form = UserDetails()
    user = Users.query.get(user_id)
    admin_user = Users.query.get(current_user.id)
    if not admin_user.admin:
        abort(403)
        return redirect(url_for('main.home'))
    
    if request.method == 'POST':
        if user_update_form.validate_on_submit():            
            if user:
                current_app.logger.info("Updating details for user - " + user_update_form.username.data)
                user.name = (user_update_form.username.data).strip()
                if user_update_form.useractive.data == 'True':
                    user.active = True
                else:
                    user.active = False
                if user_update_form.orguser.data == 'True':
                    user.org_user = True
                else:                    
                    user.org_user = False
                db.session.commit()
                flash("User details updated.",'success')
                current_app.logger.info("User details updated")
                return redirect(url_for('users.manage_users'))
    elif request.method == 'GET':
        current_app.logger.info("Populating info about user")
        user_update_form.username.data = user.name
        user_update_form.useractive.data = user.active
        user_update_form.orguser.data = user.org_user

    return render_template('update_user.html', title = 'Update User', form=user_update_form)

    
'''
Route for deleting users
Only enterrpise admin can do this
'''
@users.route("/delete_user/<int:user_id>", methods=['GET', 'POST'])
def delete_user(user_id):
    current_app.logger.info("Initiating user deletion")
    if not current_user.is_authenticated and session['user'] != current_user.id:
        logout_user()
        return redirect(url_for('main.home'))
    
    user_delete_form = DeleteUser()        
    admin_user = Users.query.get(current_user.id)
    if not admin_user.admin:
        abort(403)
        return redirect(url_for('main.home'))

    user = Users.query.get(user_id)
    
    if user is not None:
        if request.method == 'GET':
            user_delete_form.email.data = user.email # read-only field
                
        elif request.method == 'POST':
            if user_delete_form.submit.data:
                current_app.logger.warning("Deleting user - " + str(user_delete_form.email.data))
                db.session.delete(user)
                db.session.commit()
                flash("User deleted.",'success')
                current_app.logger.warning("User deleted - " + user_delete_form.email.data)
                return redirect(url_for('users.manage_users'))         
            elif user_delete_form.cancel.data:
                current_app.logger.info("Not deleting any user now.")       
                            

    return render_template('delete_user.html', title = 'Delete User', form=user_delete_form, user = user)

    