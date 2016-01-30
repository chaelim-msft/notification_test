from flask import Flask, abort, request
import base64
import json
from uuid import uuid4
import requests
import requests.auth
from urllib.parse import urlencode

# Steps to run
# 1. Run "ngrok http 65010"
# 2. Update reply url from https://windows.azure-test.net
# 3. Update following URI.
NGROK_URI = "https://100fcd79.ngrok.io"

CLIENT_ID = "a256f84e-f249-4e68-8d27-bb8e97816cde"
CLIENT_SECRET = "gDvEj0dUiMq96S8HV7PqcryV5u0PxmfHyZRNXh02fwI="
#REDIRECT_URI = "http://localhost:65010/oauth_callback"
REDIRECT_URI = '{0}{1}'.format(NGROK_URI, "/oauth_callback")

# The OAuth authority.
AUTHORITY = "https://login.windows-ppe.net"

# The authorize URL that initiates the OAuth2 client credential flow for admin consent.
AUTHORIZE_URL = '{0}{1}'.format(AUTHORITY, '/common/oauth2/authorize?{0}')

# The token issuing endpoint.
TOKEN_URL = '{0}{1}'.format(AUTHORITY, '/common/oauth2/token')

#TOKEN_URI="https://login.windows-ppe.net/common/oauth2/v2.0/token"
RESOURCE_URL="https://graph.microsoft-ppe.com/"


# This function creates the signin URL that the app will
# direct the user to in order to sign in to Office 365 and
# give the app consent.
def get_signin_url(redirect_uri):
    # Build the query parameters for the signin URL.
    params = { 'client_id': CLIENT_ID,
               'redirect_uri': redirect_uri,
               'response_type': 'code'
             }

    signin_url = AUTHORIZE_URL.format(urlencode(params))
    return signin_url

# This function passes the authorization code to the token
# issuing endpoint, gets the token, and then returns it.
def get_token_from_code(auth_code, redirect_uri):
  # Build the post form for the token request
  post_data = { 'grant_type': 'authorization_code',
                'code': auth_code,
                'redirect_uri': redirect_uri,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'resource': RESOURCE_URL
              }
              
  r = requests.post(TOKEN_URL, data = post_data)

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


app = Flask(__name__)
@app.route('/')
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
    return text % get_signin_url(REDIRECT_URI)


# Left as an exercise to the reader.
# You may want to store valid states in a database or memcache.
def save_created_state(state):
    pass
def is_valid_state(state):
    return True

@app.route('/oauth_callback')
def oauth_callback():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        abort(403)

    auth_code = request.args.get('code')
    token = get_token_from_code(auth_code, REDIRECT_URI)
    access_token = token['access_token']
    user_info = get_user_info_from_token(token['id_token'])

    # Note: In most cases, you'll want to store the access token, in, say,
    # a session for use in other parts of your web app.
    return "alias = {0}, email = {1}, access token = {2}".format(
        user_info['upn'].split('@')[0],
        user_info['upn'],
        access_token)

if __name__ == '__main__':
    app.run(debug=True, port=65010)