from flask import Blueprint, render_template

views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template("home.html")

@views.route('/profile')
def profile():
    return render_template("profile.html")

@views.route('/content')
def content():
    return render_template("content.html")