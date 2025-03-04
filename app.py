from flask import Flask, request, render_template, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import string
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI", 'sqlite:///database.db')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  
db = SQLAlchemy(app)
app.secret_key = os.getenv("SECRET_KEY", "default_secret")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"] 
)

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template("login.html", error="Too many login attempts! Try again later."), 429

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    ph_number = db.Column(db.String(15), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable = False, unique= True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name, ph_number):
        self.name = name
        self.email = email
        self.ph_number = ph_number
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods= ['GET', 'POST'])
def register():
    if 'email' in session:
        return redirect('/dashboard')

    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email')
        ph_number = request.form.get('phone')
        password = request.form['password']
        confirm_password = request.form['pwd']

        if(password != confirm_password):
            return render_template('register.html', error1 = "Passwords do not match. Please try again")

        existing_user = User.query.filter_by(email=email).first()
        if(existing_user):
            return render_template('register.html', error2 = "Account already exists with this email ID")
        
        existing_user = User.query.filter_by(ph_number=ph_number).first()
        if(existing_user):
            return render_template('register.html', error4 = "Account already exists with this phone number")
        
        has_alpha = any(c.isalpha() for c in password)  
        has_digit = any(c.isdigit() for c in password)  
        has_special = any(c in string.punctuation for c in password)

        strong_password = has_alpha and has_digit and has_special

        if(strong_password == False):
            return render_template('register.html', error3 = "Please enter a strong password(it should contain alphabets, numbers, as well as special characters)")

        new_user = User(email=email, password=password, name=name, ph_number=ph_number)
        db.session.add(new_user)
        db.session.commit()
        session['email'] = email
        return redirect('/dashboard')

    return render_template('register.html')

@app.route('/login', methods= ['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'email' in session:
        return redirect('/dashboard')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form['password']
        remember_me = request.form.get('remember')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session.permanent = True if remember_me == "on" else False
            return redirect('/dashboard')
        else:
            return render_template('login.html', error = 'Invalid email or password entered!')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')

    if session.get('email'):
        user = User.query.filter_by(email= session['email']).first()
        return render_template('dashboard.html', user = user)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash("You have been logged out!")
    return redirect('/login')

@app.route('/confirm', methods= ['GET', 'POST'])
def confirm():
    if request.method == 'POST':
        email = request.form.get('email')
        ph_number = request.form.get('phone')

        user = User.query.filter_by(email= email).first()
        if(not user):
            return render_template('confirm.html', error = "No account exists with this email ID. Try again!")
        
        if user:
            if user.ph_number != ph_number:
                return render_template('confirm.html', error = "Email and phone number do not match. Please try again!")
            else : 
                session['email'] = email
                return redirect('/forgot')


    return render_template('confirm.html')

@app.route('/forgot', methods = ['GET','POST'])
def forgot():
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['pwd']

        if(password != confirm_password):
            return render_template('forgot.html', error = "Passwords do not match. Please try again")
        
        has_alpha = any(c.isalpha() for c in password)  
        has_digit = any(c.isdigit() for c in password)  
        has_special = any(c in string.punctuation for c in password)

        strong_password = has_alpha and has_digit and has_special

        if(strong_password == False):
            return render_template('forgot.html', error = "Please enter a strong password(it should contain alphabets, numbers, as well as special characters)")
        
        if 'email' not in session:
            return redirect('/login')
        
        if session.get('email'):
            email = session['email']
            user = User.query.filter_by(email= email).first()
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.session.commit()
            session.pop('email', None)
            flash("Password Changed Successfully!")
            return redirect('/login')        

    return render_template('forgot.html')

if __name__ == '__main__':
    app.run(debug=True)