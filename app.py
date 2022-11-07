from flask import Flask, url_for, redirect, render_template, g, request
from flask import render_template
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'O większego trudno zucha!'

app_info = {'db_file': './data/wc_bet.db' }

def get_db():
    
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    
    return g.sqlite_db

@app.route('/')
def index():

    db = get_db()
    sql_command = """
    select 
        m.*, 
        case when date > DATETIME('now') then 1 else 0 end as dostepny
    from matches m
    order by date asc
    """
    c = db.execute(sql_command)
    matches = c.fetchall()

    return render_template('index.html', matches=matches)

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        return render_template('signup.html')