import forms

from config import app, db, bcrypt, User
from flask import render_template, request, redirect, url_for
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy.exc import IntegrityError
import random
import string
@app.route('/')
def base():
    if forms.RegistrationForm().validate_on_submit():
        # Creating a new user in the database
        register_form = forms.RegistrationForm()
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(username=register_form.username.data,
                    email=register_form.email.data,
                    password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            return redirect(url_for('base'))
        # Signing in the user after creating them
        user = User.query.filter_by(email=forms.RegistrationForm().email.data).first()
        if user and bcrypt.check_password_hash(user.password, forms.RegistrationForm().password.data):
            login_user(user)
            # Taking the user to the authenticated side of the site
            return redirect(url_for('base'))

    if forms.LoginForm().validate_on_submit():
        user = User.query.filter_by(email=forms.LoginForm().email.data).first()
        if user and bcrypt.check_password_hash(user.password, forms.LoginForm().password.data):
            login_user(user, remember=forms.LoginForm().remember.data)
            #print(current_user.get_all_image_links())
            return redirect(url_for('base'))

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):
        logout_user()
        return redirect(url_for('base'))

    return render_template('base.html',
                           login_form=forms.LoginForm(),
                           register_form=forms.RegistrationForm())


if __name__ == "__main__":
    app.run(debug=True)

