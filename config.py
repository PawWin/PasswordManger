import os
import sqlite3

from flask import Flask
from flask_login import UserMixin, current_user, login_manager
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from sqlalchemy import create_engine

app = Flask(__name__,  template_folder='./templates')

bcrypt = Bcrypt(app)

# Adding cross site forgery protection
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
csrf = CSRFProtect(app)

# User authentication set up
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)


# DataBase object configuration
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False)
    websiteData = db.relationship('WebsiteData', backref='user', lazy=True)


class WebsiteData(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    WebsiteName = db.Column(db.String(60), nullable=False)
    WebsiteURL = db.Column(db.String(255), nullable=True)
    WebsiteUserName = db.Column(db.String(255), nullable=True)
    WebsitePassword = db.Column(db.String(255), nullable=False)


def get_user_websites():
    if current_user.is_authenticated:
        user_id = current_user.id
        user_websites = WebsiteData.query.filter_by(user_id=user_id).all()
        return user_websites
    else:
        return None


