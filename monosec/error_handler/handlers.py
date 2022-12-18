from flask import Blueprint, render_template

errors = Blueprint('errors', __name__)

'''
Error Handler module so that users do not end up seeing ugly texts
and instead land up at a page with appropriate message
'''

'''
Method to handle 401 error response
'''
@errors.app_errorhandler(401)
def error_401(error):
    return render_template('pages/401.html'), 401


'''
Method to handle 403 error response
'''
@errors.app_errorhandler(403)
def error_403(error):
    return render_template('pages/403.html'), 403


'''
Method to handle 404 error response
'''
@errors.app_errorhandler(404)
def error_404(error):
    return render_template('pages/404.html'), 404


'''
Method to handle 500 error response
'''
@errors.app_errorhandler(500)
def error_500(error):
    return render_template('pages/500.html'), 500


'''
Method to handle 501 error response
'''
@errors.app_errorhandler(501)
def error_501(error):
    return render_template('pages/501.html'), 501


'''
Method to handle 502 error response
'''
@errors.app_errorhandler(502)
def error_502(error):
    return render_template('pages/502.html'), 502
