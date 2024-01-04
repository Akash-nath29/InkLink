from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
#TODO: Write the database model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
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


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # try:
        #     auth.sign_in_with_email_and_password(email, password)
        #     session['user_id'] = user.id  
        #     flash('Login Successful', 'Success')
        #     return redirect(url_for('dashboard'))
        # except:
        #     flash('Enter Proper email and password', 'danger')
        #     return redirect(url_for('login'))



        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('/auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']


        # try:
        #     auth.create_user_with_email_and_password(email, password)
        #     hashed_password = generate_password_hash(password)

        #     new_user = User(username=username, email=email, password=hashed_password)

        #     db.session.add(new_user)
        #     db.session.commit()

        #     flash('Registration successful! You can now log in.', 'success')
        #     return redirect(url_for('login'))
        # except:
        #     flash('Username or email already exists. Please choose a different one.', 'danger')
        #     return redirect(url_for('register'))


        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'danger')
        else:
            hashed_password = generate_password_hash(password)

            new_user = User(username=username, email=email, password=hashed_password)

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('/auth/register.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
        flash('You have been logged out.', 'info')
    else:
        flash('You are not currently logged in.', 'warning')

    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)