import os
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager

app = Flask(__name__)

app.config.from_object('config')

app.config['SESSION_TYPE'] = 'memory'
app.secret_key = "GraphNotificationTest"

db = SQLAlchemy(app)
lm = LoginManager()
lm.init_app(app)

from app import views