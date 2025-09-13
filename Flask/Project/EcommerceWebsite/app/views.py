from flask import Blueprint, render_template
from .auth import current_user

views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template('home.html',user = current_user)

@views.route('/aboutus')
def about_us():
    return render_template('aboutus.html',user = current_user)

@views.route('/contact')
def contact():
    return render_template('contact.html',user = current_user)
