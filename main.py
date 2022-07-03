import string
from flask import Flask, render_template, session, url_for, redirect, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
from atexit import register
from io import BytesIO
from werkzeug.utils import secure_filename
import os

#Create application and required configs
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'mostsecretkeyevermade'

UPLOAD_FOLDER = 'static/dataSets/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Database Class
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(20), nullable=False, unique=False)
    lastName = db.Column(db.String(20), nullable=False, unique=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    adminControl = db.Column(db.String(80), nullable=False)
    dateCreated = db.Column(db.String(80), nullable=False)
    lastLogin = db.Column(db.String(80), nullable=False)

# Registeration Form----------------------------------------------------------------------------------------------------
class RegisterForm(FlaskForm):
    firstName = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "First Name"})
    lastName = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Last Name"})
    email = StringField(validators=[InputRequired(), Length(
        min=6, max=40)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=40)], render_kw={"placeholder": "Password"})
    adminControl = PasswordField(validators=[Length(min=8, max=20)], render_kw={
                                 "placeholder": "Admin Password (Optional)"})
    now = datetime.now()
    dateCreated = now.strftime("%d/%m/%Y %H:%M:%S")
    lastLogin = now.strftime("%d/%m/%Y %H:%M:%S")

    submit = SubmitField('Register')

    def validate_email(self, email):
        if existing_user_email := User.query.filter_by(email=email.data).first():
            raise ValidationError(
                'That email already exists. Please choose a different one.')

    def validate_admin(self, adminControl):
        return "NotAdmin" if self.adminControl.data != "Admin12345" else "admin"

# Login form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(
        min=3, max=30)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=20)], render_kw={"placeholder": "Password"})
    now = datetime.now()
    lastLogin = now.strftime("%d/%m/%Y %H:%M:%S")

    submit = SubmitField('Login')

# Dashboard form
class DashForm(FlaskForm):
    dataSet = FileField()
    graphType = SelectField('Data Set', choices=[('line', 'Line Graph'), ('bar', 'Bar Graph'), ('radar', 'Radar Graph'), (
        'doughnut_pie', 'Doughnut & Pie Graph'), ('polar', 'Polar Graph'), ('bubble', 'Bubble Graph'), ('scatter', 'Scatter Graph')])

    submit = SubmitField('Submit')

#Profile Form --- unfinished
class ProfileForm(FlaskForm):
    firstName = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "First Name"})
    lastName = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Last Name"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Email"})

    submit = SubmitField('Submit')

# Page Routes-------------------------------------------------------------------------------------------------------------
@app.route('/') # Index page
def home():
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST']) # Admin page - successful access
@login_required
def admin():
    user = current_user
    if user.adminControl != "admin":
        return render_template("adminDeny.html")
    data = User.query.all()
    return render_template("admin.html", data=data)


@app.route('/profile', methods=['GET', 'POST']) # Profile page - edit user information
@login_required
def profile():
    form = ProfileForm()
    user = current_user

    if form.validate_on_submit():
        curr_user = User.query.filter_by(email=form.email.data).first()
        curr_user.firstName = form.firstName.data
        curr_user.lastName = form.lastName.data
        curr_user.email = form.email.data
        db.session.commit()
        user = current_user
        form = ProfileForm()
        render_template("profile.html", user=user, form=form)

    return render_template("profile.html", user=user, form=form)


@app.route('/dashboard', methods=['GET', 'POST']) # Dashboard page - Form for creating graph here, data sent to /content
@login_required
def dashboard():
    form = DashForm()

    if form.validate_on_submit():
        f = form.dataSet.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(UPLOAD_FOLDER, filename))
        session['dataSet'] = form.dataSet.data.filename
        session['graphType'] = form.graphType.data
        session['DOWNLOAD_PATH'] = UPLOAD_FOLDER + filename

        return redirect(url_for('content'))

    return render_template("dashboard.html", form=form)


@app.route('/content', methods=['GET', 'POST']) # Content page - Reads data from /dashboard then creates graph using chart.js --- unfinished
@login_required
def content():
    with open(session['DOWNLOAD_PATH'], 'r') as txt_file:
        data = txt_file.readlines()

    data = [x[:-1] for x in data]  # Removing all endlines
    # Getting labels------------------
    labels = data[0]
    labels = labels.replace('"', '')
    labels = labels.replace(' ', '')
    labels = labels.split(',')
    # --------------------------------
    new_data = data[1:]

    return render_template("content.html", labels=labels, data=new_data, col=len(labels))

@app.route('/admin/action/id=<userid>', methods=['GET', 'POST']) 
@login_required
def delete(userid):
    a_user = User.query.filter(User.id == userid).one()
    if a_user.adminControl == 'banned':
        a_user.adminControl = 'NotAdmin'
    else:
        a_user.adminControl = 'banned'         
        
    db.session.commit()
    data = User.query.all()
    return render_template("admin.html", data=data)

# Chart routes--------------------------------------------------------------------------------------------------
@app.route("/bar_chart")
def bar_chart():
    return render_template('bar_chart.html', title='Bar Chart')


@app.route("/line_chart")
def line_chart():
    return render_template('line_chart.html', title='Line Chart')


@app.route("/pie_chart")
def pie_chart():
    return render_template('pie_chart.html', title='Pie Chart')

# Auth Routes-------------------------------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST']) # Login page - authenticates incoming users, forwards to /dashboard if successful
def login():
    logout_user()
    form = LoginForm()

    if form.validate_on_submit():
        if user := User.query.filter_by(email=form.email.data).first():
            if bcrypt.check_password_hash(user.password, form.password.data) and user.adminControl != 'banned':
                login_user(user)
                curr_user = User.query.filter_by(email=form.email.data).first()
                curr_user.lastLogin = form.lastLogin
                db.session.commit()
                return redirect(url_for('dashboard'))

    return render_template("login.html", form=form)


@app.route('/sign-up', methods=['GET', 'POST']) # Sign up page - allows user to create profile, forwards to /login if successful
def sign_up():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        adminAccess = form.validate_admin(form.adminControl.data)
        new_user = User(firstName=form.firstName.data, lastName=form.lastName.data, email=form.email.data,
                        password=hashed_password, adminControl=adminAccess, dateCreated=form.dateCreated, lastLogin=form.lastLogin)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("signup.html", form=form)


@app.route('/logout', methods=['GET', 'POST']) # Logout button - log user out, then forwards to /login
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Database routes-----------------------------------------------------------------------------------------------------------
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    db.create_all()
    if request.method == 'POST':
        file = request.files['file']

        upload = User(filename=file.filename, data=file.read())
        db.session.add(upload)
        db.session.commit()

        return f'Uploaded: {file.filename}'
    return render_template('upload.html')


@app.route('/download/<upload_id>')
def download(upload_id):
    upload = User.query.filter_by(id=upload_id).first()
    return send_file(BytesIO(upload.data), attachment_filename=upload.filename, as_attachment=True)
# ------------------------------------------------------------------------------------------------------------

# MAIN CALL
if __name__ == '__main__':
    app.run(debug=True)
