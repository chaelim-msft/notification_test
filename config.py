import os
basedir = os.path.abspath(os.path.dirname(__file__))

# Steps to run
# 1. Run "ngrok http 65050"
# 2. Update reply url from https://windows.azure-test.net
# 3. Update following URI.
NGROK_URI = "https://568ae2b2.ngrok.io"

REDIRECT_URI = '{0}{1}'.format(NGROK_URI, "/oauth_callback/{0}")

# The OAuth authority.
AUTHORITY_PPE = "https://login.windows-ppe.net"
AUTHORITY_PROD = "https://login.windows.net"

# The authorize URL that initiates the OAuth2 client credential flow for admin consent.
AUTHORIZE_URL = {
    "test" : '{0}{1}'.format(AUTHORITY_PPE, '/common/oauth2/authorize?{0}'),
    "ppe" : '{0}{1}'.format(AUTHORITY_PPE, '/common/oauth2/authorize?{0}'),
    "prod" : '{0}{1}'.format(AUTHORITY_PROD, '/common/oauth2/authorize?{0}')
}

# The token issuing endpoint.
TOKEN_URL = {
    "test" : '{0}{1}'.format(AUTHORITY_PPE, '/common/oauth2/token'),
    "ppe" : '{0}{1}'.format(AUTHORITY_PPE, '/common/oauth2/token'),
    "prod" : '{0}{1}'.format(AUTHORITY_PROD, '/common/oauth2/token'),
}

RESOURCE_URL = {
    "test" : "https://graph.microsoft-ppe.com/",
    "ppe" : "https://graph.microsoft-ppe.com/",
    "prod" : "https://graph.microsoft-ppe.com/"
}

if os.environ.get('DATABASE_URL') is None:
    SQLALCHEMY_DATABASE_URI = ('sqlite:///' + os.path.join(basedir, '_app.db') +
                               '?check_same_thread=False')
else:
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
SQLALCHEMY_RECORD_QUERIES = True

# slow database query threshold (in seconds)
DATABASE_QUERY_TIMEOUT = 0.5
