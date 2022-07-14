from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import timedelta

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

###LOGIN MANAGERsss
login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# Line below only required once, when creating DB.
# db.create_all()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)

@app.route('/')

def home():
    return render_template("index.html")


@app.route('/register',methods=['POST','GET'])
def register():
    check = db.session.query(User).filter_by(email=request.form.get('email')).first()

    if not check and request.method=="POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password_to_hash = request.form.get('password')
        hashed_password = generate_password_hash(password=password_to_hash, method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=name,
                        email=email,
                        password=hashed_password,
                        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    elif check:
        error = "You've already signed up with that email, log in instead!"
        return render_template("login.html", error=error)


    return render_template("register.html")


@app.route('/login',methods=['POST','GET'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user:
            error = f"Email address {email} not found. Kindly confirm or register an account"
        elif check_password_hash(user.password,password):
            login_user(user)
            flash("Successfully logged in!!")
            return redirect(url_for("secrets"))
        else:
            error="Invalid password"

    return render_template("login.html",error=error)

@app.route('/secrets')
@login_required
def secrets():
    user_name = current_user.name
    print(user_name)
    return render_template("secrets.html",user_name=user_name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<path:filename>',methods=['GET', 'POST'])
@login_required
def download(filename):
    return send_from_directory(directory=app.static_folder,path=f'files/{filename}',as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
