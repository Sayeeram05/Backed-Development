from hmac import new
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        from app.models import User
                
        current_user = User.query.filter_by(email=email).first()

        if current_user and current_user.password == password:
            login_user(current_user)
            flash('Logged in successfully!', category='success')
            return redirect(url_for('views.home'))
        else:
            flash('Login failed. Check your email and password.', category='error')
            return redirect(url_for('auth.login'))
    else:
        return render_template('login.html',user = None)
    

@auth.route('signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        print(email, password, confirm_password)
        
        from app.models import User
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(password) < 7:
            flash('Password must be at least 7 characters.', category='error')
        elif password != confirm_password:
            flash('Passwords do not match.', category='error')
        else:
            new_user = User(email=email, password=password)
            print(email, password)
            from . import db
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', category='success')
            login_user(new_user)
            return redirect(url_for('views.home'))

    return render_template('signup.html', user=None)

@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('views.home'))