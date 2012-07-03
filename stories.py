import time
import sqlite3
from contextlib import closing
from flaskext.bcrypt import Bcrypt
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash


# config
DATABASE = '/tmp/stories.db'
DEBUG = True
SECRET_KEY = 'development key'


# create app!
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('STORIES_SETTINGS', silent=True) # override!
bcrypt = Bcrypt(app)


def connect_db():
    """Rerturns a new connection to the db."""
    return sqlite3.connect(app.config['DATABASE'])


def init_db():
    """Creates db tables."""
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    """Queries the db and returns a list of dictionaries."""
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
                for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Gets the id for a given username."""
    rv = g.db.execute('select user_id from users where username = ?',
                      [username]).fetchone()
    return rv[0] if rv else None


@app.before_request
def before_request():
    """Make sure we're connected to the db and user is loaded."""
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from users where user_id = ?',
                          [session['user_id']], one=True)


@app.teardown_request
def teardown_request(exception):
    """Closes down the db..."""
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/')
def show_stories():
    cur = g.db.execute('select title, text from stories order by story_id desc')
    stories = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
    return render_template('show_stories.html', stories=stories)


@app.route('/<username>')
def show_user_stories():
    """Shows all the stories of a given username"""
    pass


@app.route('/add', methods=['POST'])
def add_story():
    if not session.get('user_id'):
        abort(401)
    g.db.execute('''insert into stories (author_id, title, text, pub_date) 
        values (?, ?, ?, ?)''', (session['user_id'], request.form['title'], 
                                 request.form['text'], int(time.time())))
    g.db.commit()
    flash('New entry was successfully posted')
    return redirect(url_for('show_stories'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in!"""
    if g.user:
        return redirect(url_for('show_stories'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from users where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not bcrypt.check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('show_stories'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('show_stories'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            g.db.execute('''insert into users (
                username, email, pw_hash) values (?, ?, ?)''',
                [request.form['username'], request.form['email'],
                 bcrypt.generate_password_hash(request.form['password'])])
            g.db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs user out?!"""
    session.pop('user_id', None)
    flash('You were logged out')
    return redirect(url_for('show_stories'))


if __name__ == '__main__':
    app.run()
