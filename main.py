import random
import string
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_mail import Mail, Message
import json

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'noreply.staybatu@gmail.com'
app.config['MAIL_PASSWORD'] = 'shepwmxhuxbpgqpw'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
posta = Mail(app)

app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(100))
    alamat = db.Column(db.String(1000))
    telp = db.Column(db.String(20))
    token = db.Column(db.String(120))
    passwordset = db.relationship('Passwords')

class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app = db.Column(db.String(1000))
    password = db.Column(db.String(1000))
    id_user = db.Column(db.Integer, db.ForeignKey('user.id'))


db.create_all()


@app.route('/')
def home():
    # Every render_template has a logged_in variable set.
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        # Hashing
        hash_password = generate_password_hash(
            request.form.get('password'),
            method='md5',
        )
        new_user = User(
            email=request.form.get('email'),
            username=request.form.get('username'),
            alamat=request.form.get('alamat'),
            telp=request.form.get('telp'),
            password=hash_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets', methods=["GET", "POST"])
@login_required
def secrets():
    if request.method == "POST":
        id = request.form.get('id')
    print(current_user.username)
    return render_template("secrets.html", user=current_user, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/reset', methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.", category="error")
            return redirect(url_for('reset'))
        else:
            token = ''.join(random.choices(
                string.ascii_letters + string.digits, k=24))
            user.token = token
            db.session.commit()
            msg = Message('Confirm Password Change',
                          sender='noreply.staybatu@gmail.com', recipients=[email])
            msg.body = f"Hello,\nWe've received a request to reset your password. If you want to reset your password, click the link below and enter your new password\n http://localhost:5000/reset/{user.token}"
            posta.send(msg)
            flash("Please check your email for password reset!", category="success")

    return render_template("reset.html")


@app.route("/reset/")
@app.route("/reset/<string:token>", methods=["GET", "POST"])
def token(token):
    user = User.query.filter_by(token=token).first()
    if not user:
        flash("Invalid token, please try again.")
        return redirect(url_for('reset'))
    else:
        if request.method == 'POST':
            passw = request.form.get('passw')
            cpassw = request.form.get('cpassw')
            if passw == cpassw:
                user.password = generate_password_hash(
                    passw,
                    method='md5',
                )
                user.token = None
                db.session.commit()
                flash("Your password has been changed. Please login.")
                return redirect(url_for('login'))
            else:
                flash('Password and confirm password must be the same')

    return render_template('change_password.html')

@app.route('/addPassword', methods=["GET", "POST"])
@login_required
def addPassword():
    if request.method == "POST":
        # Hashing
        hash_password = generate_password_hash(
            request.form.get('password'),
            method='md5',
        )
        new_password = Passwords(
            app=request.form.get('app'),
            password=hash_password,
            id_user=current_user.id
        )
        db.session.add(new_password)
        db.session.commit()
        return redirect(url_for("secrets"))

    return render_template("addPassword.html", user=current_user, logged_in=True)

@app.route('/delete-pass', methods=['POST'])
def delete_pass():
    passw = json.loads(request.data)
    passId = passw['passId']
    passw = Passwords.query.get(passId)
    if passw:
        if passw.id_user == current_user.id:
            db.session.delete(passw)
            db.session.commit()

    return jsonify({})

if __name__ == "__main__":
    app.run(debug=True)
