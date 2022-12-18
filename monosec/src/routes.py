from flask import Blueprint, render_template, session, current_app


main = Blueprint('main',__name__)

@main.route("/")
def home():
    current_app.logger.info("Routing to home now.")    
    return render_template('home.html')