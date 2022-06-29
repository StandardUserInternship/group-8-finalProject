from flask import Flask, render_template, session, url_for, redirect, request, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo, DataRequired
from flask_bcrypt import Bcrypt
from datetime import datetime
from atexit import register
from io import BytesIO
from werkzeug.utils import secure_filename

#imports for user account profile picture---------------------------------------------
import os
import secrets
from PIL import Image
from flaskblog import app, db, bcrypt, routes
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm
from flaskblog.models import User, Post
from flask_wtf.file import FileField, FileAllowed
-------------------------------------------------------------------------------------

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' 
app.config['SECRET_KEY'] = 'mostsecretkeyevermade'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#User Class
class User(db.Model, UserMixin):
    
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(20), nullable=False, unique=False)
    lastName = db.Column(db.String(20), nullable=False, unique=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    adminControl = db.Column(db.String(80), nullable=False)
    dateCreated = db.Column(db.String(80), nullable=False)
    lastLogin = db.Column(db.String(80), nullable=False)
    
#User account profile picture-------------------------------------------------------------------------------------------
    image_file = db.Column(db.String(80), nullable=False, default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"
    
 class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

#Registeration Form----------------------------------------------------------------------------------------------------
class RegisterForm(FlaskForm):
    firstName = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "First Name"})
    lastName = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Last Name"})
    email = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    adminControl = PasswordField(validators=[Length(min=8, max=20)], render_kw={"placeholder": "Admin Password (Optional)"})
    now = datetime.now()
    dateCreated = now.strftime("%d/%m/%Y %H:%M:%S")
    lastLogin = now.strftime("%d/%m/%Y %H:%M:%S")

    submit = SubmitField('Register')

    def validate_email(self, email):
        if existing_user_email := User.query.filter_by(email=email.data).first():
            raise ValidationError('That email already exists. Please choose a different one.')

    def validate_admin(self, adminControl):
        return "NotAdmin" if self.adminControl.data != "Admin12345" else "admin"

#Login form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#Login form
class DashForm(FlaskForm):
    dataSet = FileField()
    graphType = SelectField('Data Set', choices=[('line', 'Line Graph'), ('bar', 'Bar Graph'), ('radar', 'Radar Graph')
    , ('doughnut_pie', 'Doughnut & Pie Graph'), ('polar', 'Polar Graph'), ('bubble', 'Bubble Graph'), ('scatter', 'Scatter Graph')])

    submit = SubmitField('Submit')

#Page Routes-------------------------------------------------------------------------------------------------------------
@app.route('/') 
def home():
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    user = current_user
    if user.adminControl != "admin": 
        return render_template("adminDeny.html")
    data = User.query.all()
    return render_template("admin.html", data=data)

@app.route('/profile')
@login_required 
def profile():
    user = current_user
    return render_template("profile.html", user=user)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required 
def dashboard():
    form=DashForm()

    if form.validate_on_submit():
        filename = secure_filename(form.dataSet.data.filename)
        session['dataSet'] = filename 
        session['graphType'] = form.graphType.data
        if form.graphType.data == 'line':
            return render_template("line_chart.html")
        elif form.graphType.data =='bar':
            return render_template("bar_chart.html")
        elif form.graphType.data =='doughnut_pie':
            return render_template("pie_chart.html")
        return redirect(url_for('content'))

    return render_template("dashboard.html", form=form)

@app.route('/content', methods=['GET', 'POST'])
@login_required 
def content():
    return render_template("content.html")

#Chart routes--------------------------------------------------------------------------------------------------
@app.route("/bar_chart")
def bar_chart():
    #can add legend and other headers later and change the example data to data from db
    return render_template('bar_chart.html', title ='Bar Chart')

@app.route("/line_chart")
def line_chart():
    return render_template('line_chart.html', title ='Line Chart')

@app.route("/pie_chart")
def pie_chart():
    return render_template('pie_chart.html', title = 'Pie Chart')

#Auth Routes-------------------------------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    logout_user()
    form = LoginForm()

    if form.validate_on_submit():
        if user := User.query.filter_by(email=form.email.data).first():
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
 
    return render_template("login.html", form=form)

@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        adminAccess = form.validate_admin(form.adminControl.data)
        new_user = User(firstName=form.firstName.data, lastName=form.lastName.data, email=form.email.data,
         password=hashed_password, adminControl=adminAccess, dateCreated=form.dateCreated, lastLogin = form.lastLogin)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("signup.html", form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Database routes-----------------------------------------------------------------------------------------------------------
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
#------------------------------------------------------------------------------------------------------------

#route for user account profile picture----------------------------------------------------------------------
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)
--------------------------------------------------------------------------------------------------------------------

#MAIN CALL
if __name__ == '__main__':
    app.run(debug=True)

