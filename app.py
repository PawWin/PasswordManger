import forms

from config import app, db, bcrypt, User, get_user_websites, WebsiteData, encrypt_password, decrypt_password
from flask import render_template, request, redirect, url_for
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy.exc import IntegrityError
import random
import string


@app.route('/', methods=['GET', 'POST'])
def base():
    if forms.RegistrationForm().validate_on_submit():
        register_form = forms.RegistrationForm()
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(fullname=register_form.fullname.data,
                    email=register_form.email.data,
                    password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            return redirect(url_for('base'))
        user = User.query.filter_by(email=forms.RegistrationForm().email.data).first()
        if user and bcrypt.check_password_hash(user.password, forms.RegistrationForm().password.data):
            login_user(user)
            return redirect(url_for('base'))

    if forms.LoginForm().validate_on_submit():
        user = User.query.filter_by(email=forms.LoginForm().email.data).first()
        if user and bcrypt.check_password_hash(user.password, forms.LoginForm().password.data):
            login_user(user)
            return redirect(url_for('base'))

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):
        logout_user()
        return redirect(url_for('base'))

    return render_template('base.html',
                           login_form=forms.LoginForm(),
                           register_form=forms.RegistrationForm())


@app.route('/index', methods=['GET', 'POST'])
def index():
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

    '''if (request.method == "POST") & (request.form.get('post_header') == 'delete'):
        website_data_id = request.form.get('website_data_id')
        website_data = WebsiteData.query.filter_by(id=website_data_id).first()
        db.session.delete(website_data)
        db.session.commit()
        return redirect(url_for('index'))'''

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):
        logout_user()
        return redirect(url_for('index'))

    user_websites = get_user_websites()
    for website in user_websites:
        website.WebsitePassword = decrypt_password(website.WebsitePassword)

    return render_template('index.html',
                           website_data_form=forms.WebsiteDataForm(),
                           user_websites=user_websites,user=current_user)




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

