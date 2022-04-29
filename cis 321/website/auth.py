from flask import Flask, Blueprint, render_template, request, flash, redirect, url_for, session, abort
from .models import User,AdminUser
from werkzeug.security import generate_password_hash, check_password_hash
from . import db,db2
from flask_login import login_user, login_required, logout_user, current_user
import sqlite3
import os.path
from google_auth_oauthlib.flow import Flow
import os
import pathlib
import requests
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token



auth = Blueprint('auth', __name__)

app = Flask(__name__,template_folder='templates')
app.secret_key = "djfijifjdsijidfj"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "515926037822-arq98lmdq7gvinsoebe9tfd6seji65n9.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


currentdirectory = os.path.dirname(os.path.abspath(__file__))
con =sqlite3.connect(currentdirectory + '\compamy.db', check_same_thread=False)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/google_login')
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@auth.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    if 'dome.tu.ac.th' in session["email"]:
        flash("welcome")
    else:
        return redirect(url_for('auth.error'))
    return redirect("/protected_area")

@auth.route('/protected_area')
@login_is_required
def protected_area():
    return render_template("home.html", user=current_user)

@auth.route('/error')
def error():
    return render_template("error.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('views.beforelogin'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        studentid = request.form.get('studentid')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 10:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(studentid) < 10:
            flash('Student ID must be 10 characters.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email,studentid=studentid, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('auth.add_student'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/company')
def company():
         with con:
            cur=con.cursor() 
            query1= "select * from Company "
            cur.execute(query1)
            rows= cur.fetchall()
         return render_template("company.html",datas=rows, user=current_user)          

@auth.route('/job1', methods=['GET', 'POST'])
def job1():
        with con:
            atitle = request.args.get('t')
            cur=con .cursor() 
            query1= "select * from Job_Position where Company_ID = "+str(atitle)
            cur.execute(query1)
            rows= cur.fetchall()
        return render_template("job1.html",datas2=rows, user=current_user)


@auth.route('/sign-up-staff', methods=['GET', 'POST'])
def sign_up_staff():
    if request.method == 'POST':
        adminid = request.form.get('adminid')
        adminpassword1 = request.form.get('adminpassword1')
        adminpassword2 = request.form.get('adminpassword2')

        user2 = AdminUser.query.filter_by(adminid=adminid).first()
        if user2:
            flash('Admin ID already exists.', category='error')
        elif len(adminid) < 7:
            flash('Admin ID must be 7 characters.', category='error')
        elif adminpassword1 != adminpassword2:
            flash('Passwords don\'t match.', category='error')
        elif len(adminpassword1) < 13:
            flash('Password must be  13 characters.', category='error')
        else:
            new_user2 = AdminUser(adminid=adminid, adminpassword=generate_password_hash(
                adminpassword1, method='sha256'))
            db2.session.add(new_user2)
            db2.session.commit()
            login_user(user2, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home_staff'))

    return render_template("sign_up_staff.html", user2=current_user)

@auth.route('/login_staff', methods=['GET', 'POST'])
def login_staff():
    if request.method == 'POST':
        adminid = request.form.get('adminid')
        adminpassword = request.form.get('adminpassword')

        user2 = AdminUser.query.filter_by(adminid=adminid).first()
        if user2:
            if check_password_hash(user2.adminpassword, adminpassword):
                flash('Logged in successfully!', category='success')
                login_user(user2, remember=True)
                return redirect(url_for('views.home_staff'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Admin ID does not exist.', category='error')

    return render_template("login_staff.html", user2=current_user)

@auth.route('/logout_staff')
@login_required
def logoutadmin():
    logout_user()
    return redirect(url_for('views.beforelogin'))

@auth.route('/com_staff')
def company_staff():
         with con:
            cur=con.cursor() 
            query1= "select * from Company "
            cur.execute(query1)
            rows= cur.fetchall()
         return render_template("com_staff.html",datas=rows, user2=current_user)          

@auth.route('/job_staff')
def job_staff():
        with con:
            atitle = request.args.get('t')
            cur=con .cursor() 
            query1= "select * from Job_Position where Company_ID = "+str(atitle)
            cur.execute(query1)
            rows= cur.fetchall()
        return render_template("job_staff.html",datas2=rows, user2=current_user)

@auth.route("/add_com")
def add_com():
    return render_template("add_com.html", user2=current_user)

@auth.route("/add_job")
def add_job():
    return render_template("add_job.html", user2=current_user)

@auth.route('/add_student')
def add_student():
    return render_template("add_student.html", user=current_user)

