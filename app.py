from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
import sqlite3
import os
import pyotp
import qrcode
import io
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Setup Flask-Login
login_manager = LoginManager();
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_NAME = 'users.db'

# User class
class User(UserMixin):
    def __init__(self, id, username, password_hash, totp_secret):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.totp_secret = totp_secret

# DB Setup
if not os.path.exists(DB_NAME):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password_hash TEXT, totp_secret TEXT)''')
    conn.commit()
    conn.close()

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, totp_secret FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(*user)
    return None

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        totp_secret = pyotp.random_base32()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)", (username, password_hash, totp_secret))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, totp_secret FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['pre_2fa_user'] = user
            return redirect(url_for('verify_2fa'))
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    user_data = session['pre_2fa_user']
    totp = pyotp.TOTP(user_data[3])

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            user = User(*user_data)
            login_user(user)
            session.pop('pre_2fa_user', None)
            return redirect(url_for('success'))
        else:
            return "Invalid 2FA Code"

    return render_template('verify_2fa.html')

@app.route('/qrcode')
def qr_code():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))
    user_data = session['pre_2fa_user']
    otp_uri = pyotp.TOTP(user_data[3]).provisioning_uri(name=user_data[1], issuer_name="FlaskSecureApp")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/success')
@login_required
def success():
    return render_template('success.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
