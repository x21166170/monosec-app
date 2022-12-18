from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, InputRequired

'''
Form used to update user information
Can be done only by the enterprise administrator
'''
class UserDetails(FlaskForm):
    username = StringField('UserName', validators=[DataRequired(), Length(min=3, max=40)])
    useractive = RadioField('UserActive', choices=[('True', 'User is active'), ('False', 'User is inactive')], validators=[InputRequired()])
    orguser = RadioField('OrgUser', choices=[('True', 'Internal User'), ('False', 'Not Internal User')], validators=[InputRequired()])
    submit = SubmitField('Update')

'''
Form used to delete user - deletion deletes all posts and comments created by the user (cascade delete)
Can be done only by the enterprise administrator
'''
class DeleteUser(FlaskForm):
    email = StringField('UserEmail', render_kw={'readonly': True})
    submit = SubmitField('Delete')
    cancel = SubmitField('Cancel')