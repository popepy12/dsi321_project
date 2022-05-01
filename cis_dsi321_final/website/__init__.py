from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User

    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app

def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')


db2 = SQLAlchemy()
DB_NAME2 = "admindatabase.db"


def create_app2():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME2}'
    db2.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import AdminUser

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login_staff'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return AdminUser.query.get(int(id))

    create_database(app)

    return app

def create_database(app):
    if not path.exists('website/' + DB_NAME2):
        db2.create_all(app=app)
        print('Created Database!')   