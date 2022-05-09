from flask import Blueprint, render_template
from flask_login import login_required, current_user

views = Blueprint('views', __name__)



@views.route('/home')
@login_required
def home():
    return render_template("home.html", user=current_user)

@views.route('/home_staff')
@login_required
def home_staff():
    return render_template("home_staff.html", user2=current_user)

@views.route('/')
def beforelogin():
    return render_template("before_login.html", user=current_user)