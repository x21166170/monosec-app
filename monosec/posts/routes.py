from flask import Blueprint, redirect, url_for, render_template, flash, abort, request, session, current_app
from flask_login import login_user, current_user, logout_user, login_required
from monosec.models import Posts, Comments, Users
from monosec.posts.forms import CreatePost, AddComments, UpdatePost
from monosec import db

posts = Blueprint('posts',__name__)

'''
Route for main portal view that lists all the issues created by the user
Admin can see all the posts, edit or delete them
Enterprise user can see all the posts, and add comments
'''
@posts.route("/portal")
@login_required
def portal():
    current_app.logger.info("Initiating portal now")
    if not current_user.is_authenticated and session['user'] != current_user.id:
        flash("Need authorization to view the page", 'error')
        logout_user()
        current_app.logger.warning("User not authorized, redirecting " + str(current_user.id))
        return redirect(url_for('auth.reset_request'))
    if not current_user.active:
        flash("Need authorization to view the page", 'error')
        current_app.logger.warning("User not active, redirecting " + str(current_user.id))
        return redirect(url_for('main.home'))
        
    # Get the posts now (based on organizatin user or external user we filter the results)
    all_posts = None
    if current_user.org_user:
        current_app.logger.warning("User is an internal user" + str(current_user.id))
        all_posts = Posts.query.all()
    else:
        current_app.logger.warning("User is an external user" + str(current_user.id))
        all_posts = Posts.query.filter_by(user_id=current_user.id).all()            
    return render_template('portal.html',posts=all_posts, admin = current_user.admin, name = current_user.name)
    
    
'''
Route for creating a new post
'''
@posts.route("/create_post",methods=['GET', 'POST'])
@login_required
def create_post():
    current_app.logger.info("Initiaiting create post - " + str(current_user.id))
    if not current_user.is_authenticated and session['user'] != current_user.id:
        flash("Need authorization to view the page", 'error')
        logout_user()
        return redirect(url_for('main.home'))
    create_post_form = CreatePost()
    if request.method == 'POST':
        if create_post_form.validate_on_submit():
            post_title = (create_post_form.title.data).strip()
            post_content = (create_post_form.details.data).strip()
            new_post = Posts(title=post_title, content=post_content, author=current_user)
            db.session.add(new_post)
            db.session.commit()
            flash("Issue added sucessfully", 'success')
            current_app.logger.info("Post created " + new_post.title)
            return redirect(url_for('posts.portal'))
    return render_template('create_post.html', form = create_post_form, title='Create New Post')
    
'''
Route for seeing the details of a post
'''
@posts.route("/post/<int:post_id>")
@login_required
def post(post_id):
    current_app.logger.info("Retrieving post details for post - " + str(post_id))
    if not current_user.is_authenticated and session['user'] != current_user.id:
        flash("Need authorization to view the page", 'error')
        logout_user()
        return redirect(url_for('main.home'))
    if not current_user.is_authenticated:
        return redirect(url_for('main.home'))
    post = Posts.query.get_or_404(post_id)
    user = Users.query.get(current_user.id)
    if not user.admin and not user.org_user:
        if post.author != current_user:
            current_app.logger.warning("Post author is not current user")
            abort(403)
    current_app.logger.info("User permitted to view post - " + str(current_user.id))
    current_post = Posts.query.get_or_404(post_id)
    user = Users.query.get(current_user.id)
    if current_post:
        return render_template('post.html', post=current_post, user=user)
    
    
'''
Route for updating a post
'''
@posts.route("/update_post/<int:post_id>",methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    current_app.logger.info("Updating post - " + str(post_id))
    if not current_user.is_authenticated and session['user'] != current_user.id:
        flash("Need authorization to view the page", 'error')
        logout_user()
        return redirect(url_for('main.home'))
    user = Users.query.get(current_user.id)
    post = Posts.query.get_or_404(post_id)
        
    if user and post:
        if not user.admin and not user.org_user:
            if post.author != current_user:
                current_app.logger.warning("Post author is not current user, Cannot update" + str(current_user.id))
                abort(403)
        current_app.logger.info("User permitted to edit post - " + str(current_user.id))      
        update_post_form = UpdatePost()
        if request.method == 'POST':
            if update_post_form.validate_on_submit():
                post.title = (update_post_form.title.data).strip()
                post.content = (update_post_form.details.data).strip()
                if update_post_form.status.data == 'True':
                    post.status = 1
                else:
                    post.status = 0
                db.session.commit()
                flash('Post has been updated', 'success')
                current_app.logger.info("Post has been updated'- " + str(post_id))
                return redirect(url_for('posts.portal'))
        elif request.method == 'GET':
            current_app.logger.info("Getting details of post - " + str(post_id))
            update_post_form.title.data = post.title
            update_post_form.details.data = post.content
            update_post_form.submit.label.text = 'Update Post'
    return render_template('update_post.html', title='Update Post', form = update_post_form, user = user)

'''
Route for seeing all the comments for a specific post
the user who has creaed the post can view the comments
Enterprise admin or users can see these comments as well and add new comments
'''
@posts.route("/comments/<int:post_id>")
@login_required
def comments(post_id):
    current_app.logger.info("Getting all comments for " + str(post_id))
    if not current_user.is_authenticated and session['user'] != current_user.id:
        flash("Need authorization to view the page", 'error')
        logout_user()
        current_app.logger.warning("User is not authorized to view comments " + str(current_user.id))
        return redirect(url_for('main.home'))
        
    post = Posts.query.get_or_404(post_id)
    user = Users.query.get(current_user.id)
    if not user.admin and not user.org_user:        
        if post.author != current_user:
            current_app.logger.warning("Post author is not current user, Cannot view comments" + str(current_user.id))
            abort(403)
    current_app.logger.info("User permitted to view the post comments for post - " + str(post_id))
    all_post_comments= Comments.query.filter_by(post_id=post_id).all()
    return render_template('comments.html',comments=all_post_comments, post_id=post_id)
    

'''
Route for adding comments to a specific post
the user who has creaed the post can add  comments
Enterprise admin or users can also add new comments
'''
@posts.route("/add_comment/<int:post_id>",methods=['GET', 'POST'])
@login_required
def add_comment(post_id):
    current_app.logger.info("Adding comments to post " + str(post_id))
    if not current_user.is_authenticated and session['user'] != current_user.id:
        flash("Need authorization to view the page", 'error')
        logout_user()
        current_app.logger.warning("User is not authorized to view comments " + str(current_user.id))
        return redirect(url_for('main.home'))
        
    user = Users.query.get(current_user.id)
    post = Posts.query.get(post_id)
    if not user.admin and not user.org_user:
        if post.author != current_user:
            current_app.logger.warning("Post author is not current user, Cannot view comments" + str(current_user.id))
            abort(403)
    add_comment_form = AddComments()
    if request.method == 'POST':
        if add_comment_form.validate_on_submit():
            current_post = Posts.query.get_or_404(post_id)
            #Posts.query.filter_by(id=post_id).all()
            if current_post:
                comment_title = (add_comment_form.title.data).strip()
                comment_text = (add_comment_form.title.data).strip()
                new_comment = Comments(title=comment_title, text=comment_text, post_id=post_id ,author=current_user)
                db.session.add(new_comment)
                db.session.commit()
                flash("Comment added sucessfully", 'success')
                current_app.logger.info("Comment added sucessfully to post - " + str(post_id) + " by user - " + str(current_user.id))
            else:
                current_app.logger.error("No post found for - " + str(post_id))                    
            return redirect(url_for('posts.comments', post_id=post_id))
    return render_template('add_comment.html', form = add_comment_form)
    
    