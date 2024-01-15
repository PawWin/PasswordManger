from io import BytesIO
import pyqrcode
import forms
from config import app, db, bcrypt, User, get_user_websites, WebsiteData, encrypt_password, decrypt_password, delete_website_data
from flask import render_template, request, redirect, url_for, session, abort, flash
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy.exc import IntegrityError
import random
import string
from pyqrcode import QRCode


@app.route('/', methods=['GET', 'POST'])
def base():
    if forms.RegistrationForm().validate_on_submit():
        register_form = forms.RegistrationForm()
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(username=register_form.username.data,
                    email=register_form.email.data,
                    password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            session['username'] = user.username
            return redirect(url_for('two_factor_setup'))
        except IntegrityError:
            return redirect(url_for('base'))

    if forms.LoginForm().validate_on_submit():
        user = User.query.filter_by(email=forms.LoginForm().email.data).first()
        if user is None or not bcrypt.check_password_hash(user.password, forms.LoginForm().password.data) or \
                not user.verify_totp(forms.LoginForm().token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('base'))
        if user and bcrypt.check_password_hash(user.password, forms.LoginForm().password.data):
            login_user(user)
            return redirect(url_for('base'))

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):
        logout_user()
        return redirect(url_for('base'))

    return render_template('base.html',
                           login_form=forms.LoginForm(),
                           register_form=forms.RegistrationForm())

@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('base'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('base'))
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    del session['username']

    url = QRCode(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/index', methods=['GET', 'POST'])
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('base'))
    if forms.WebsiteDataForm().validate_on_submit():
        website_data_form = forms.WebsiteDataForm()
        encrypted_password = encrypt_password(website_data_form.WebsitePassword.data)
        website_data = WebsiteData(WebsiteName=website_data_form.WebsiteName.data,
                                   WebsiteURL=website_data_form.WebsiteURL.data,
                                   WebsiteUserName=website_data_form.WebsiteUserName.data,
                                   WebsitePassword=encrypted_password,
                                   user_id=current_user.id)
        db.session.add(website_data)
        db.session.commit()
        return redirect(url_for('index'))

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):
        logout_user()
        return redirect(url_for('index'))

    delete_form = forms.DeleteWebsiteDataForm()
    if delete_form.validate_on_submit():
        website_id_to_delete = delete_form.hidden_argument.data
        delete_website_data(website_id_to_delete)
        return redirect(url_for('index'))

    return render_template('index.html',
                           website_data_form=forms.WebsiteDataForm(),
                           user_websites=get_user_websites(),user=current_user,delete_form=delete_form)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

