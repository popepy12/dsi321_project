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
con =sqlite3.connect(currentdirectory + '\dbnew.db', check_same_thread=False)


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


@auth.route('/add_student', methods=['GET', 'POST'])
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


@auth.route('/add_staff', methods=['GET', 'POST'])
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
            login_user(new_user2, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('auth.add_staff'))

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

@auth.route('/success')
def add_student():
    return render_template("success.html", user=current_user)

@auth.route('/success_staff')
def add_staff():
    return render_template("success_staff.html", user=current_user)

@auth.route("/insertjob1",methods=['POST','GET'])
def insertjob1():
    if request.method=="POST":
        with con:
            Job_Position_ID = request.form['Job_Position_ID']
            Company_ID= request.form['Company_ID']
            User_Staff_ID= request.form['User_Staff_ID']
            Job_Position_Name =request.form['Job_Position_Name']
            Job_Amount_Required = request.form['Job_Amount_Required']
            Compensation= request.form['Compensation']
            Job_Description= request.form['Job_Description']
            Position_Qualification= request.form['Position_Qualification']
            Working_Period= request.form['Working_Period']
            Application_Deadline= request.form['Application_Deadline']
            Job_Position_Link =request.form['Job_Position_Link']
            cur=con .cursor()
            sql="Insert into Job_Position (Job_Position_ID , Company_ID, User_Staff_ID, Job_Position_Name, Job_Amount_Required, Compensation, Job_Description, Position_Qualification, Working_Period, Application_Deadline, Job_Position_Link) values(?,?,?,?,?,?,?,?,?,?,?)"
            cur.execute(sql,(Job_Position_ID , Company_ID, User_Staff_ID, Job_Position_Name, Job_Amount_Required, Compensation, Job_Description, Position_Qualification, Working_Period, Application_Deadline, Job_Position_Link))
            con.commit()
        return redirect(url_for('auth.company_staff'))

@auth.route("/delete/<string:id_data>",methods=['GET'])
def delete(id_data):
    with con:
        id_data = id_data
        cur=con.cursor()
        cur.execute("delete from Company where Company_ID ="+str(id_data))
        con.commit()
    return redirect(url_for('auth.company_staff'))

@auth.route("/update",methods=['POST'])
def update():
    if request.method=="POST":
        companyid_update=request.form['Company_ID']
        Company_Name =request.form['Company_Name']
        Company_Type =request.form['Company_Type']
        Established_Date =request.form['Established_Date']
        with con:
            cur=con .cursor()
            sql ="update Company set Company_Name=?,Company_Type=?,Established_Date=? where Company_ID=?"
            cur.execute(sql,(Company_Name,Company_Type,Established_Date,companyid_update))
            con.commit()
        return redirect(url_for('auth.company_staff'))
@auth.route("/deletejob1/<string:id_data>",methods=['GET'])
def deletejob1(id_data):
    with con:
        id_data = id_data
        cur=con.cursor()
        cur.execute("delete from Job_Position where Job_Position_ID ="+str(id_data))
        con.commit()
    return redirect(url_for('auth.company_staff'))
    
@auth.route("/updatejob1",methods=['POST'])
def updatejob1():
    if request.method=="POST":
        jobid_update=request.form['Job_Position_ID']
        Job_Position_Name =request.form['Job_Position_Name']
        Job_Description=request.form['Job_Description']
        Position_Qualification =request.form['Position_Qualification']
        Working_Period =request.form['Working_Period']
        Job_Position_Link =request.form['Job_Position_Link']
        with con:
            cur=con .cursor()
            sql ="update Job_Position set Job_Position_Name=?,Job_Description=?,Position_Qualification=?, Working_Period=?, Job_Position_Link=? where Job_Position_ID=?"
            cur.execute(sql,(Job_Position_Name,Job_Description,Position_Qualification,Working_Period,Job_Position_Link,jobid_update))
            con.commit()
        return redirect(url_for('auth.company_staff'))

@auth.route("/insert",methods=['POST','GET'])
def insert():
    if request.method=="POST":
        with con:
            Company_ID = request.form['Company_ID']
            User_Staff_ID= request.form['User_Staff_ID']
            Company_Name =request.form['Company_Name']
            Company_Photo=request.form['Company_Photo']
            Company_Type = request.form['Company_Type']
            Company_Address= request.form['Company_Address']
            Company_Email= request.form['Company_Email']
            Contact_Number= request.form['Contact_Number']
            Fax_Number= request.form['Fax_Number']
            Established_Date =request.form['Established_Date']
            Company_Details= request.form['Company_Details']
            Company_Link= request.form['Company_Link']
            Status=request.form['Status']
            cur=con .cursor()
            sql="Insert into Company (Company_ID , User_Staff_ID,Company_Photo,Company_Address,Company_Email,Contact_Number,Fax_Number,Company_Name,Company_Details,Company_Link,Company_Type,Established_Date,Status) values(?,?,?,?,?,?,?,?,?,?,?,?,?)"
            cur.execute(sql,(Company_ID , User_Staff_ID,Company_Photo,Company_Address,Company_Email,Contact_Number,Fax_Number,Company_Name,Company_Details,Company_Link,Company_Type,Established_Date,Status))
            con.commit()
        return redirect(url_for('auth.company_staff'))