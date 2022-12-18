from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, InputRequired
from monosec.auth.validations import validate_input

'''
Form for creating new posts
'''
class CreatePost(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=8, max=200)])
    details = TextAreaField('Details', validators=[DataRequired(), Length(min=8, max=300)])
    submit = SubmitField('Add')

    '''
    Method to validate the post title
    '''
    def validate_title(self,title):
        validate_input(title.data)

    '''
    Method to validate the text input for issues
    '''
    def validate_details(self,details):
        validate_input(details.data)

'''
Form for updating an already existing post
'''
class UpdatePost(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=8, max=200)])
    details = TextAreaField('Details', validators=[DataRequired(), Length(min=8, max=300)])
    status = RadioField('Status', choices=[('True', 'Open'), ('False', 'Closed')], validators=[InputRequired()])
    submit = SubmitField('Update')
    
    '''
    Method to validate the post title
    '''
    def validate_title(self,title):
        validate_input(title.data)

    '''
    Method to validate the text input for issues
    '''
    def validate_details(self,details):
        validate_input(details.data)

'''
Form for adding comments to a post
'''
class AddComments(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=8, max=200)])
    details = StringField('Comment', validators=[DataRequired(), Length(min=8, max=200)])
    submit = SubmitField('Add')

    '''
    Method to validate the comment title
    '''
    def validate_title(self,title):
        validate_input(title.data)
        
    '''
    Method to validate the text input for comments
    '''
    def validate_details(self,details):
        validate_input(details.data)