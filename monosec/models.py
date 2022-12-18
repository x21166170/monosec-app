
from flask import current_app
from monosec import db, login_manager
from datetime import datetime
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Database Models
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(24), nullable=False)
    active = db.Column(db.Boolean, default=False, nullable=False)
    sso_user = db.Column(db.Boolean, default=False, nullable=False)
    org_user = db.Column(db.Boolean, default=False, nullable=False)
    admin = db.Column(db.Boolean, default=False, nullable=False)
    posts = db.relationship('Posts', backref='author', lazy=True, cascade='delete')
    comments = db.relationship('Comments', backref='author', lazy=True, cascade='delete')
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    """__repr__ returns <type 'Users'>"""
    def __repr__(self):
        return Users(' {self.email} ', '{self.active}','{self.active}', '{self.admin}')  
    
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], 300)
        return s.dumps(self.email,salt='password-reset-salt')

    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_email = s.loads(token,salt='password-reset-salt') 
        except:
            return None
        return Users.query.filter_by(email=user_email).first()

   
class Posts(db.Model,UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150),nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    update_date = db.Column(db.DateTime)
    content = db.Column(db.Text, nullable=False)    
    status = db.Column(db.Integer, default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    """__repr__ returns <type 'Posts'>"""
    def __repr__(self):
        return Posts('{self.title}', '{self.content}', '{self.date}', '{self.status}')

class Comments(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)    
    title = db.Column(db.Text, nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)   
    
    """__repr__ returns <type 'Comments'>"""
    def __repr__(self):
        return Comments('{self.title}' '{self.text}', '{self.date}') 