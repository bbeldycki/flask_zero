import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))
        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)
    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/profile')
def profile():
    return render_template('auth/profile.html')


@bp.route('/edit', methods=('GET', 'POST'))
def edit():
    if request.method == 'POST':
        firstname = request.form['firstname']
        # secondname = request.form['secondname']
        # phone_number = request.form['phone_number']
        db = get_db()

        # db.execute(
        #    'INSERT INTO user (firstname, secondname, phone_number) VALUES (?, ?, ?)',
        #    (firstname, secondname, phone_number)
        # )
        db.execute(
            'INSERT INTO user (firstname) VALUES (?)',
            (firstname,)
        )
        db.commit()
        return redirect(url_for('auth.profile'))
    return render_template('auth/edit.html')


@bp.route('/home', methods=('GET', 'POST'))
def home():
    pass
    return redirect(url_for('index'))


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)
    return wrapped_view
'''
{% if g.user %}
    <div>
      <a class="action" href="{{ url_for('profiles.edit') }}">Edit profile</a>
    </div>
    <div>
      <a class="action" href="{{ url_for('profiles.clear') }}"
         onclick="return confirm('Are you sure?');">Clear profile</a>
    </div>
  {% endif %}
  
    <label for="secondname">Second name</label>
    <input name="secondname" id="secondname" value="{{ request.form['secondname'] }}">
    <label for="pnumber">Phone number</label>
    <input name="pnumber" id="pnumber" value="{{ request.form['phone_number'] }}">
'''
