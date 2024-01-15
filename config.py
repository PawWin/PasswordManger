import os
import sqlite3
import base64
import onetimepass
from flask import Flask
from flask_login import UserMixin, current_user, login_manager
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from sqlalchemy import create_engine
from cryptography.fernet import Fernet


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


# Load or generate the key for encryption and decryption
ENCRYPTION_KEY_FILE = 'encryption_key.key'

if os.path.exists(ENCRYPTION_KEY_FILE):
    with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
        key_file.write(key)

cipher_suite = Fernet(key)

# Function to encrypt a password
def encrypt_password(password):
    encrypted_password = cipher_suite.encrypt(password.encode('utf-8'))
    return encrypted_password


# Function to decrypt an encrypted password
def decrypt_password(encrypted_password):
    decrypted_password = cipher_suite.decrypt(encrypted_password)
    return decrypted_password.decode('utf-8')


def delete_website_data(website_data_id):
    website_data = WebsiteData.query.filter_by(id=website_data_id).first()
    db.session.delete(website_data)
    db.session.commit()


# DataBase object configuration
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False)
    websiteData = db.relationship('WebsiteData', backref='user', lazy=True)
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')


    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


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
        for website in user_websites:
            try:
                website.decrypted_password = decrypt_password(website.WebsitePassword)
            except Exception as e:
                # Handle decryption errors, you might want to log or handle them appropriately
                website.decrypted_password = "Decryption Error"

        return user_websites
    else:
        return None

