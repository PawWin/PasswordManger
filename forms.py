from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class RegistrationForm(FlaskForm):
    fullname = StringField('Username',validators=[DataRequired(), Length(min=2, max=300)],render_kw={"class": "form-style"})
    email = StringField('Email', validators=[DataRequired(), Email()],render_kw={"class": "form-style"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"class": "form-style"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')],render_kw={"class": "form-style"})
    submit = SubmitField('Sign Up',render_kw={"class": "btn mt-4"})


class LoginForm(FlaskForm):
    email = StringField('Email', validators = [DataRequired(), Email()],render_kw={"class": "form-style"})
    password = PasswordField('Password', validators = [DataRequired()],render_kw={"class": "form-style"})
    submit = SubmitField('Login',render_kw={"class": "btn mt-4"})


class WebsiteDataForm(FlaskForm):
    WebsiteName = StringField('Website Name', validators=[DataRequired()],render_kw={"class": "form-style"})
    WebsiteURL = StringField('Website URL', validators=[DataRequired()],render_kw={"class": "form-style"})
    WebsiteUserName = StringField('Website User Name', validators=[DataRequired()],render_kw={"class": "form-style"})
    WebsitePassword = StringField('Website Password', validators=[DataRequired()],render_kw={"class": "form-style"})
    submit = SubmitField('Submit',render_kw={"class": "btn btn-success"})

class DeleteWebsiteDataForm(FlaskForm):
    submit = SubmitField('Delete',render_kw={"class": "btn btn-danger"})