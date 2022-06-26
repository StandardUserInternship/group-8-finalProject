from atexit import register
import bcrypt
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy.sql import text

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' 
app.config['SECRET_KEY'] = 'This is a secretkey!'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(20), nullable=False, unique=False)
    lastName = db.Column(db.String(20), nullable=False, unique=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

#Registeration Form
class RegisterForm(FlaskForm):
    firstName = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "First Name"})
    lastName = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Last Name"})
    email = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_email(self, email):
        if existing_user_email := User.query.filter_by(email=email.data).first():
            raise ValidationError('That email already exists. Please choose a different one.')

#Login form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#Page Routes
@app.route('/') 
def home():
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required 
def dashboard():
    return render_template("dashboard.html")

@app.route('/profile')
@login_required 
def profile():
    return render_template("profile.html")

@app.route('/content')
@login_required 
def content():
    return render_template("content.html")

#Auth Routes
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
        new_user = User(firstName=form.firstName.data, lastName=form.lastName.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("signup.html", form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Chart routes
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
    
#Database routes
@app.route('/db')
def testdb():
    try:
        db.session.query(text('1')).from_statement(text('SELECT 1')).all()
        return '<h1>It works.</h1>'
    except Exception as e:
        # e holds description of the error
        error_text = "<p>The error:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text

#MAIN CALL
if __name__ == '__main__':
    app.run(debug=True)
