from flask import Flask, url_for, redirect, render_template, g, request, flash, session
from flask import render_template
import sqlite3

import string
import hashlib
import binascii

app = Flask(__name__)
app.config['SECRET_KEY'] = 'O większego trudno zucha!'

app_info = {'db_file': './data/wc_bet.db' }

def get_db():
    
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    
    return g.sqlite_db

class Users:

    def __init__(self, user='', password=''):
        self.user = user
        self.password = password

    def hash_password(self):
        os_urandom_static =b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'),
        salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def login_user(self):

        db = get_db()
        query = 'select id, login, password, is_admin from users where login=?'
        c = db.execute(query, [self.user])
        user_record = c.fetchone()

        if user_record != None and self.user != '' and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None

        

@app.route('/')
def index():

    db = get_db()

    query  = """
    select 
        m.*, 
        case when date > DATETIME('now') then 1 else 0 end as dostepny
    from matches m
    order by date asc
    """
    c = db.execute(query)
    matches = c.fetchall()

    return render_template('index.html', matches=matches)

@app.route('/signup', methods=['GET','POST'])
def signup():

    if request.method == 'GET':
        return render_template('signup.html')

    else:

        if request.form['psw'] != request.form['psw2']:
            flash('Hasła są różne')
            return render_template('signup.html')

        db = get_db()

        login = request.form['login']
        email = request.form['email']
        password = request.form['psw']

        if login == '' or email == '' or password == '':
            flash('Formularz zawiera puste wartości')
            return render_template('signup.html')

        query = """
        select count(*) as cnt
        from users
        where email = ?
        or login = ?
        """

        c = db.execute(
            query, [email, login])

        n_users = c.fetchone()

        if n_users['cnt'] != 0:
            flash('Użytkownik o podanym loginie lub emailu istnieje')
            return render_template('signup.html')

        query = """
        insert into users (login, email, password)values (?, ?, ?)
        """
        
        userpass = Users(login, password)
        password_hash = userpass.hash_password()

        db.execute(query, [login, email, password_hash])
        db.commit()

        flash('Rejestracja pomyślna')
        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():

        user_name = '' if 'login' not in request.form else request.form['login']
        user_pass = '' if 'psw' not in request.form else request.form['psw']
        
        login = Users(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            
            session['user'] = user_name
            flash(f'Logowanie pomyślne, witaj {user_name}')
        
            return redirect(url_for('index'))
        else:
            
            flash('Logowanie nie powiodło się')
            return redirect(url_for('index'))

@app.route('/logout', methods=['POST'])
def logout():

    if 'user' in session:
        session.pop('user', None)

    flash('Wylogowano')
    return redirect(url_for('index'))

@app.route('/typuj/<int:match_id>', methods=['POST'])
def typuj_mecz(match_id):

    if 'user' not in session:
        flash('Nie jesteś zalogowany')
        return redirect(url_for('index'))

    db = get_db()

    query = """
    delete from bets 
    where login = ?
    and id_match = ? 
    """
    try:
        db.execute(query, [session['user'], match_id])
        db.commit()
    except:
        pass

    query = """
    insert into bets (login, id_match, home_score, away_score)
    values (?, ?, ?, ?)
    """

    db.execute(
        query,
        [session['user'], 
        match_id, 
        request.form['home_score'],
        request.form['away_score']
    ])

    db.commit()

    flash('Wytypowano wynik meczu')
    return redirect(url_for('index'))
