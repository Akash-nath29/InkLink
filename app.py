from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from datetime import datetime
from dotenv import find_dotenv, load_dotenv
import secrets
from authlib.integrations.flask_client import OAuth
from os import environ as env
from urllib.parse import quote_plus, urlencode
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = secrets.token_hex(64)
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)
oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    redirect_uri=env.get("AUTH0_CALLBACK_URL"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

#TODO: Write the database model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=True, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    bio = db.Column(db.Text(1000), nullable=True)
    profile_picture = db.Column(db.String, default='static/img/default.png')
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_title = db.Column(db.String(500), nullable=False)
    post_content = db.Column(db.Text, nullable=False)
    post_banner = db.Column(db.String, default='static/img/defaultBanner.png')
    likes = db.Column(db.Integer)
    dislikes = db.Column(db.Integer)
    posted_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

admin = Admin(app)
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Post, db.session))

@app.route('/')
def index():
    return render_template('index.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
#         user = User.query.filter_by(email=email).first()
#         if user and check_password_hash(user.password, password):
#             flash('Login successful!', 'success')
#             session['user_id'] = user.id
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Login failed. Check your username and password.', 'danger')

#     return render_template('/auth/login.html')

@app.route('/login')
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route('/callback')
def callback():
    try:
        token = oauth.auth0.authorize_access_token()
        userinfo = oauth.auth0.parse_id_token(token, nonce=session.get('nonce'))
        session["user"] = userinfo
        # print(userinfo)

        # Check if the user already exists in the local database
        user = User.query.filter_by(email=userinfo['email']).first()

        if not user:
            # If the user doesn't exist, create a new user in the local database
            user = User(username=userinfo['nickname'], email=userinfo['email'], profile_picture=userinfo['picture'])
            db.session.add(user)
            db.session.commit()

        # Store the user information in the session
        session['user'] = userinfo

        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error during callback: {str(e)}', 'danger')
        return redirect('/')

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route('/dashboard')
def dashboard():
    user = session.get('user', None)
    if not user:
        return redirect(url_for('login'))
    posts = Post.query.order_by(desc(Post.id)).all()
    users = User.query.order_by(desc(User.id)).all()
    return render_template('dashboard.html', posts=posts, users=users)

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['password']
#         existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

#         if existing_user:
#             flash('Username or email already exists. Please choose a different one.', 'danger')
#         else:
#             hashed_password = generate_password_hash(password)

#             new_user = User(username=username, email=email)

#             db.session.add(new_user)
#             db.session.commit()

#             flash('Registration successful! You can now log in.', 'success')
#             return redirect(url_for('login'))

#     return render_template('/auth/register.html')

# @app.route('/logout')
# def logout():
#     if 'user_id' in session:
#         session.pop('user_id', None)
#         flash('You have been logged out.', 'info')
#     else:
#         flash('You are not currently logged in.', 'warning')

#     return redirect(url_for('home'))

@app.route('/add_blog', methods=['GET', 'POST'])
def add_blog():
    if request.method == 'POST':
        post_title = request.form.get('post_title')
        post_content = request.form.get('post_content')
        post_banner = request.form.get('post_banner', 'static/img/defaultBanner.png')  # Default if not provided
        user_id = user_id = session['user']['sub']  # Replace with the actual user ID (you may need to implement user authentication)

        if not post_title or not post_content:
            flash('Title and content are required.', 'danger')
        else:
            post = Post(
                post_title=post_title,
                post_content=post_content,
                post_banner=post_banner,
                likes=0,
                dislikes=0,
                posted_at=datetime.utcnow(),  # Adjust timezone as needed
                user_id=user_id
            )

            db.session.add(post)
            db.session.commit()

            flash('Blog post added successfully!', 'success')
            return redirect(url_for('dashboard'))  # Adjust the route as needed

    return render_template('add_blog.html', title='Add Blog')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)