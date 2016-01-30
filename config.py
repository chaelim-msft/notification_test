import os
basedir = os.path.abspath(os.path.dirname(__file__))

# APP info: You can get it from https://windows.azure-test.net
CLIENT_ID = "a256f84e-f249-4e68-8d27-bb8e97816cde"
CLIENT_SECRET = "gDvEj0dUiMq96S8HV7PqcryV5u0PxmfHyZRNXh02fwI="

# Steps to run
# 1. Run "ngrok http 65010"
# 2. Update reply url from https://windows.azure-test.net
# 3. Update following URI.
NGROK_URI = "https://100fcd79.ngrok.io"

REDIRECT_URI = '{0}{1}'.format(NGROK_URI, "/oauth_callback")

# The OAuth authority.
AUTHORITY = "https://login.windows-ppe.net"

# The authorize URL that initiates the OAuth2 client credential flow for admin consent.
AUTHORIZE_URL = '{0}{1}'.format(AUTHORITY, '/common/oauth2/authorize?{0}')

# The token issuing endpoint.
TOKEN_URL = '{0}{1}'.format(AUTHORITY, '/common/oauth2/token')

RESOURCE_URL="https://graph.microsoft-ppe.com/"

if os.environ.get('DATABASE_URL') is None:
    SQLALCHEMY_DATABASE_URI = ('sqlite:///' + os.path.join(basedir, 'app.db') +
                               '?check_same_thread=False')
else:
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
SQLALCHEMY_RECORD_QUERIES = True

# slow database query threshold (in seconds)
DATABASE_QUERY_TIMEOUT = 0.5
