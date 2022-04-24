from flask import Flask, Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
import sqlite3
import os.path


auth = Blueprint('auth', __name__)

app = Flask(__name__,template_folder='templates')

oauth = OAuth(app)

app.config['SECRET_KEY'] = "THIS SHOULD BE SECRET"
app.config['GOOGLE_CLIENT_ID'] = "514908716404-jc4a5b3utle2b8tfaokeppul5s751td0.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"

google = oauth.register(
    name = 'google',
    client_id = app.config["GOOGLE_CLIENT_ID"],
    client_secret = app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
    authorize_params = None,
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs = {'scope': 'openid email profile'},
)

currentdirectory = os.path.dirname(os.path.abspath(__file__))
con =sqlite3.connect(currentdirectory + '\compamy.db', check_same_thread=False)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        studentid = request.form.get('studentid')
        password = request.form.get('password')

        user = User.query.filter_by(studentid=studentid).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Student ID does not exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/login/google')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('auth.google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


# Google authorize route
@auth.route('/login/google/authorize')
def google_authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo').json()
    print(f"\n{resp}\n")
    return render_template("home.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        studentid = request.form.get('studentid')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(studentid=studentid).first()
        if user:
            flash('Student ID already exists.', category='error')
        elif len(studentid) < 10:
            flash('Student ID must be 10 characters.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(studentid=studentid, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/company')
def company():
         with con:
            cur=con.cursor() 
            query1= "select * from Company "
            cur.execute(query1)
            rows= cur.fetchall()
         return render_template("company.html",datas=rows, user=current_user)          

@auth.route('/job1')
def job1():
        with con:
            atitle = request.args.get('t')
            cur=con .cursor() 
            query1= "select * from Job_Position where Company_ID = "+str(atitle)
            cur.execute(query1)
            rows= cur.fetchall()
        return render_template("job1.html",datas2=rows, user=current_user)
        