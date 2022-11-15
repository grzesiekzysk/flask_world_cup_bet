from flask import Flask, url_for, redirect, render_template, g, request, flash, session
from flask import render_template
import sqlite3

import hashlib
import binascii
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'O większego trudno zucha!'

app_info = {'db_file': './data/wc_bet.db' }

def get_db():
    
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    
    return g.sqlite_db

def get_random_string():
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(10))
    return result_str

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

    if not 'user' in session:
        flash('Nie jesteś zalogowany')
        return redirect(url_for('signup'))

    db = get_db()

    query  = """
    select 
        t.*,
        --case when date > DATETIME('now') then 1 else 0 end as dostepny,
        1 as dostepny,
        case when t.result = t.result_bet then 1 else 0 end +
        case when (t.home_score = t.home_score_bet) 
            and (t.away_score = t.away_score_bet) then 3 else 0 end 
        as points
        
    from	(select 
            m.*,
            case 
                when m.home_score = m.away_score then 0
                when m.home_score > m.away_score then 1
                when m.home_score < m.away_score then 2
            end result,
            
            b.home_score as home_score_bet,
            b.away_score as away_score_bet,
            
            case 
                when b.home_score = b.away_score then 0
                when b.home_score > b.away_score then 1
                when b.home_score < b.away_score then 2
            end result_bet

        from matches m

        left join bets b
            on m.id = b.id_match
            and b.login = ?) t
    order by date asc
    """
    c = db.execute(query, [session['user']])
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

        if email.find('@') < 0:
            flash('Email jest niepoprawny')
            return render_template('signup.html')

        if login.find(' ') > 0:
            flash('Login zawiera niedozwolone znaki')
            return render_template('signup.html')

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

    home_score, away_score = 0, 0

    if request.form['home_score'] != '':
        home_score = request.form['home_score']

    if request.form['away_score'] != '':
        away_score = request.form['away_score']

    db.execute(
        query,
        [session['user'], 
        match_id, 
        home_score,
        away_score
    ])

    db.commit()

    flash('Wytypowano wynik meczu')
    return redirect(url_for('index'))

@app.route('/leaderboard')
def leaderboard():

    if not 'user' in session:
        flash('Nie jesteś zalogowany')
        return redirect(url_for('signup'))

    db = get_db()

    query = """
    select
        login,
        sum(points) points,
        rank() over(order by sum(points) desc) ranking

    from (select 
            t.*,
            case when t.result = t.result_bet then 1 else 0 end +
            case when (t.home_score = t.home_score_bet) 
                and (t.away_score = t.away_score_bet) then 3 else 0 end 
            as points
            
        from	(
            select 
                u.login,
                m.*,
                case 
                    when m.home_score = m.away_score then 0
                    when m.home_score > m.away_score then 1
                    when m.home_score < m.away_score then 2
                end result,
                
                b.home_score as home_score_bet,
                b.away_score as away_score_bet,
                
                case 
                    when b.home_score = b.away_score then 0
                    when b.home_score > b.away_score then 1
                    when b.home_score < b.away_score then 2
                end result_bet

            from users u
                
            cross join matches m

            left join bets b
                on m.id = b.id_match
                and b.login = u.login) t) g
                
    group by login
    order by points desc
    """
    c = db.execute(query)
    users = c.fetchall()

    return render_template('leaderboard.html', users=users)

@app.route('/groups')
def groups():

    if not 'user' in session:
        flash('Nie jesteś zalogowany')
        return redirect(url_for('signup'))

    db = get_db()

    query = """
    
    """

    c = db.execute(
        query)

    groups = c.fetchall()

    return render_template('groups.html', groups=groups)

@app.route('/create_group', methods=['POST'])
def create_group():

    if not 'user' in session:
        flash('Nie jesteś zalogowany')
        return redirect(url_for('groups'))

    if request.form['new_group_name'] == '':
        flash('Nazwa grupy jest pusta')
        return redirect(url_for('groups'))

    db = get_db()

    query = """
    select count(*) cnt
    from groups 
    where nazwa_grupy = ?
    """

    c = db.execute(query, [request.form['new_group_name']])
    check = c.fetchone()

    if check['cnt'] != 0:
        flash('Nazwa grupy już występuje')
        return redirect(url_for('groups'))        

    query = """
    insert into groups (nazwa_grupy, admin, kod)
    values (?, ?, ?)
    """

    db.execute(query, [
        request.form['new_group_name'],
        session['user'],
        get_random_string()
        ])

    db.commit()

    flash('Utworzono nową grupę')
    return redirect(url_for('groups'))