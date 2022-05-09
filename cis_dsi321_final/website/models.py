from website import db
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField
from flask_restful import Resource


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    studentid = db.Column(db.String(150))
    password = db.Column(db.String(150))

class AdminUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    adminid = db.Column(db.String(150), unique=True)
    adminpassword = db.Column(db.String(150))

class Company(db.Model):
    Company_ID = db.Column(db.String(10),primary_key = True)
    Company_Name = db.Column(db.String(255))
    Company_Type = db.Column(db.String(255))
    Status = db.Column(db.String(255))

class Job_Position(db.Model):
    Job_Position_ID = db.Column(db.String(10),primary_key = True)
    Company_ID = db.Column(db.String(10))#, db.ForeignKey('company.Company_ID'))
    Job_Position_Name = db.Column(db.String(255))
    Job_Description = db.Column(db.String(255))
    Position_Qualification = db.Column(db.String(255))
    Working_Period = db.Column(db.String(255))
    Job_Position_Link = db.Column(db.String(255))


class SearchForm(FlaskForm):
     searched = StringField("searched")
     submit = SubmitField("Submit")

class companyapi(Resource):
    def get(self):
        return {"data":"pope"}
