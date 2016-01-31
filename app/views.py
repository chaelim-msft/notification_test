from flask import Flask, abort, request, render_template, redirect, session, \
    flash, g, url_for
from flask.ext.login import login_user, logout_user, current_user, LoginManager, \
    UserMixin,login_required # pip install flask-login
from flask.ext.sqlalchemy import get_debug_queries
import base64
import json
from uuid import uuid4
import requests
import requests.auth
from urllib.parse import urlencode
from config import REDIRECT_URI, AUTHORIZE_URL, TOKEN_URL, RESOURCE_URL, \
    DATABASE_QUERY_TIMEOUT
from config_secret import CLIENT_ID, CLIENT_SECRET
from datetime import datetime
from app import app, db, lm

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))

class OAuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    env = db.Column(db.String)
    email = db.Column(db.String(120))
    access_token = db.Column(db.String)
    refresh_token = db.Column(db.String)
    created_date = db.Column(db.DateTime)
  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',
        backref=db.backref('oauth_tokens', lazy='dynamic'))

    def __init__(self, env, email, access_token, refresh_token):
        self.env = env
        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.created_date = datetime.utcnow()

    def __repr__(self):
        return '<email %r>' % self.email

# Create the database if it does not exist
@app.before_first_request
def init_request():
    db.create_all()

@app.before_request
def before_request():
    g.user = current_user
    if g.user.is_authenticated:
        g.user.last_seen = datetime.utcnow()
        db.session.add(g.user)
        db.session.commit()

@app.after_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= DATABASE_QUERY_TIMEOUT:
            app.logger.warning(
                "SLOW QUERY: %s\nParameters: %s\nDuration: %fs\nContext: %s\n" %
                (query.statement, query.parameters, query.duration,
                 query.context))
    return response


@lm.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id)
    if user.count() == 1:
        return user.one()
    return None

# This function creates the signin URL that the app will
# direct the user to in order to sign in to Office 365 and
# give the app consent.
def get_signin_url(redirect_uri, env):
    # Build the query parameters for the signin URL.
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': redirect_uri.format(env),
        'response_type': 'code'
    }

    signin_url = AUTHORIZE_URL[env].format(urlencode(params))
    return signin_url

# This function passes the authorization code to the token
# issuing endpoint, gets the token, and then returns it.
def get_token_from_code(auth_code, redirect_uri, env):
    # Build the post form for the token request
    post_data = {
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri.format(env),
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': auth_code,
        'resource': RESOURCE_URL[env]
    }

    # Set verify = False to suppress SSL certificate error for Fiddler
    r = requests.post(TOKEN_URL[env], data = post_data, verify = True)
    if r.status_code != 200:
        return 'Error failed to get access token'

    try:
        return r.json()
    except:
        return 'Error retrieving token: {0} - {1}'.format(r.status_code, r.text)

# This function takes the access token and breaks it
# apart to get information about the user.
def get_user_info_from_token(id_token):
  # JWT is in three parts, header, token, and signature
  # separated by '.'.
  token_parts = id_token.split('.')
  encoded_token = token_parts[1]
  
  # Base64 strings should have a length divisible by 4.
  # If this one doesn't, add the '=' padding to fix it.
  leftovers = len(encoded_token) % 4
  if leftovers == 2:
      encoded_token += '=='
  elif leftovers == 3:
      encoded_token += '='
  
  # URL-safe base64 decode the token parts.
  decoded = base64.urlsafe_b64decode(encoded_token.encode('utf-8')).decode('utf-8')
  
  # Load decoded token into a JSON object.
  jwt = json.loads(decoded)
  
  return jwt
  
def user_agent():
    '''reddit API clients should each have their own, unique user-agent
    Ideally, with contact info included.
    
    e.g.,
    return "oauth2-sample-app by /u/%s" % your_reddit_username

    '''
    #raise NotImplementedError()
    return "cslim-test"

def base_headers():
    return {"User-Agent": user_agent()}


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


@app.route('/oauth', methods=['GET'])
def homepage():
    text = '''
<html>
  <head>
    <title>Graph Notification Test</title>
  </head>
  <body>
    <a href="%s">Get access token from Test environment</a>
  </body>
</html>
'''
    #return text % get_signin_url(REDIRECT_URI, "ppe")
    return text % "/authorize/test"

@app.route('/oauth_authorize/<env>')
@login_required
def oauth_authorize(env):
    if g.user.is_anonymous:
        return redirect(url_for('login'))

    session['env'] = env;
    return redirect(get_signin_url(REDIRECT_URI, env))

# Left as an exercise to the reader.
# You may want to store valid states in a database or memcache.
def save_created_state(state):
    pass
def is_valid_state(state):
    return True

# This is app's redirect URI called after authentication request to OAuth server.
@app.route('/oauth_callback/<env>', methods=['GET'])
def oauth_callback(env):
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        abort(403)

    auth_code = request.args.get('code')
    token = get_token_from_code(auth_code, REDIRECT_URI, env)
    access_token = token['access_token']
    
    user_info = get_user_info_from_token(token['id_token'])

    # Note: In most cases, you'll want to store the access token, in, say,
    # a session for use in other parts of your web app.
    alias = user_info['upn'].split('@')[0]
    email = user_info['upn']

    # Store in session
    session['alias'] = alias
    session['email'] = email
    session['oauth_access_token'] = access_token
    session['oauth_refresh_token'] = token['refresh_token']
 
    oauthtoken = OAuthToken( \
        email=email, env=env, \
        access_token=access_token, refresh_token=token['refresh_token'])
    db.session.add(oauthtoken)
    db.session.commit()
            
    flash('Logged in successfully.')

    return "alias = {0}, email = {1}, access token = {2}".format(
        alias,
        email,
        access_token)


@app.route('/refresh_token/<env>')
def refresh_token(env):
    # Build the post form for the token request
    post_data = {
        'grant_type': 'refresh_token',
        'refresh_token': session['oauth_refresh_token'],
        'redirect_uri': redirect_uri.format(env),
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }

    # Set verify = False to suppress SSL certificate error for Fiddler
    r = requests.post(TOKEN_URL, data = post_data, verify = True)
    if r.status_code != 200:
        return 'Error: Failed to refresh access token'

    try:
        token = r.json()
        session['oauth_access_token'] = token['access_token']
        session['oauth_refresh_token'] = token['refresh_token']
    except:
        return 'Error refresh token: {0} - {1}'.format(r.status_code, r.text)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        username = request.form['txtUsername']
        password = request.form['txtPassword']

        user = User.query.filter_by(username=username)
        if user.count() == 0:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()

            flash('You have registered the username {0}. Please login'.format(username))
            return redirect(url_for('login'))
        else:
            flash('The username {0} is already in use.  Please try a new username.'.format(username))
            return redirect(url_for('register'))
    else:
        abort(405)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', next=request.args.get('next'))
    elif request.method == 'POST':
        username = request.form['txtUsername']
        password = request.form['txtPassword']

        user = User.query.filter_by(username=username).filter_by(password=password)
        if user.count() == 1:
            login_user(user.one())
            flash('Welcome back {0}'.format(username))
            try:
                next = request.form['next']
                return redirect(next)
            except:
                return redirect(url_for('index'))
        else:
            flash('Invalid login')
            return redirect(url_for('login'))
    else:
        return abort(405)


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=65050)