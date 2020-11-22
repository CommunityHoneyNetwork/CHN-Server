from urllib.parse import urljoin

from flask import Flask, request, jsonify, abort, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore
from flask_security.utils import hash_password as hash
from flask_mail import Mail
from werkzeug.contrib.atom import AtomFeed
import xmltodict
import uuid
import random
import string
from flask_wtf.csrf import CsrfProtect
import os
import re

csrf = CsrfProtect()

db = SQLAlchemy()
# After defining `db`, import auth models due to
# circular dependency.
from mhn.auth.models import User, Role, ApiKey

user_datastore = SQLAlchemyUserDatastore(db, User, Role)

mhn = Flask(__name__)
mhn.config.from_object('config')
csrf.init_app(mhn)

# Email app setup.
mail = Mail()
mail.init_app(mhn)

# Registering app on db instance.
db.init_app(mhn)

# Setup flask-security for auth.
Security(mhn, user_datastore)

# Registering blueprints.
from mhn.api.views import api

mhn.register_blueprint(api)

from mhn.ui.views import ui

mhn.register_blueprint(ui)

from mhn.auth.views import auth

mhn.register_blueprint(auth)

# Trigger templatetag register.
from mhn.common.templatetags import format_date

mhn.jinja_env.filters['fdate'] = format_date

from mhn.auth.contextprocessors import user_ctx

mhn.context_processor(user_ctx)

from mhn.common.contextprocessors import config_ctx

mhn.context_processor(config_ctx)

import logging
from logging.handlers import RotatingFileHandler

mhn.logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s -  %(pathname)s - %(message)s')
handler = RotatingFileHandler(
    mhn.config['LOG_FILE_PATH'], maxBytes=10240, backupCount=5, encoding='utf8')
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
mhn.logger.addHandler(handler)
if mhn.config['DEBUG']:
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    mhn.logger.addHandler(console)


@mhn.route('/feed.json')
def json_feed():
    feed_content = get_feed().to_string()
    return jsonify(xmltodict.parse(feed_content))


@mhn.route('/feed.xml')
def xml_feed():
    return get_feed().get_response()


def makeurl(uri):
    baseurl = mhn.config['SERVER_BASE_URL']
    return urljoin(baseurl, uri)


def get_feed():
    from mhn.common.clio import Clio
    from mhn.auth import current_user
    authfeed = mhn.config['FEED_AUTH_REQUIRED']
    if authfeed and not current_user.is_authenticated():
        abort(404)
    feed = AtomFeed('MHN HpFeeds Report', feed_url=request.url,
                    url=request.url_root)
    sessions = Clio().session.get(options={'limit': 1000})
    for s in sessions:
        feedtext = u'Sensor "{identifier}" '
        feedtext += '{source_ip}:{source_port} on sensorip:{destination_port}.'
        feedtext = feedtext.format(**s.to_dict())
        feed.add('Feed', feedtext, content_type='text',
                 published=s.timestamp, updated=s.timestamp,
                 url=makeurl(url_for('api.get_session', session_id=str(s._id))))
    return feed


def create_clean_db():
    """
    Use from a python shell to create a fresh database.
    """
    with mhn.test_request_context():
        db.create_all()
        superuser = create_superuser_entry()

        from mhn.api.models import DeployScript
        # Creating a initial deploy scripts.
        deployscripts = {
            'Default - Conpot': os.path.abspath('./scripts/deploy_conpot.sh'),
            'Default - Dionaea': os.path.abspath('./scripts/deploy_dionaea.sh'),
            'Default - Cowrie': os.path.abspath('./scripts/deploy_cowrie.sh'),
            'Default - RDPHoney': os.path.abspath('./scripts/deploy_rdphoney.sh'),
            'Default - UHP': os.path.abspath('./scripts/deploy_uhp.sh'),
            'Default - Elasticpot': os.path.abspath('./scripts/deploy_elasticpot.sh'),
            'Default - BigHP': os.path.abspath('./scripts/deploy_big-hp.sh'),
            'Default - ssh-auth-logger': os.path.abspath('./scripts/deploy_ssh-auth-logger.sh'),
            'Default - Honeydb-Agent': os.path.abspath('./scripts/deploy_honeydb-agent.sh')
        }
        for honeypot, deploypath in sorted(deployscripts.items()):
            with open(deploypath, 'r') as deployfile:
                initdeploy = DeployScript()
                initdeploy.script = deployfile.read()
                initdeploy.notes = 'Initial deploy script for {}'.format(honeypot)
                initdeploy.user = superuser
                initdeploy.name = honeypot
                db.session.add(initdeploy)

        db.session.commit()


def create_superuser_entry():
    # Creating superuser entry.
    superuser = user_datastore.create_user(
        email=mhn.config.get('SUPERUSER_EMAIL'),
        password=hash(mhn.config.get('SUPERUSER_ONETIME_PASSWORD')))
    adminrole = user_datastore.create_role(name='admin', description='')
    user_datastore.add_role_to_user(superuser, adminrole)
    user_datastore.create_role(name='user', description='')
    db.session.flush()

    apikey = ApiKey(user_id=superuser.id, api_key=str(uuid.uuid4()).replace("-", ""))
    db.session.add(apikey)
    db.session.flush()

    return superuser


def pretty_name(name):
    # remove trailing suffix
    nosuffix = os.path.splitext(name)[0]

    # remove special characters
    nospecial = re.sub('[\'";&%#@!()*]*', '', nosuffix)

    # Convert underscore to space
    underspace = re.sub('_', ' ', nospecial)

    return underspace


def reload_scripts():
    from mhn.api.models import DeployScript

    superuser = user_datastore.get_user(mhn.config.get('SUPERUSER_EMAIL'))
    custom_path = './custom_scripts/'

    deployscripts = {
        'Default - Conpot': os.path.abspath('./scripts/deploy_conpot.sh'),
        'Default - Dionaea': os.path.abspath('./scripts/deploy_dionaea.sh'),
        'Default - Cowrie': os.path.abspath('./scripts/deploy_cowrie.sh'),
        'Default - RDPHoney': os.path.abspath('./scripts/deploy_rdphoney.sh'),
        'Default - UHP': os.path.abspath('./scripts/deploy_uhp.sh'),
        'Default - Elasticpot': os.path.abspath('./scripts/deploy_elasticpot.sh'),
        'Default - BigHP': os.path.abspath('./scripts/deploy_big-hp.sh'),
        'Default - ssh-auth-logger': os.path.abspath('./scripts/deploy_ssh-auth-logger.sh'),
        'Default - Honeydb-Agent': os.path.abspath('./scripts/deploy_honeydb-agent.sh')
    }

    f = []
    for (dirpath, dirnames, filenames) in os.walk(custom_path):
        f.extend(filenames)
        break
    for fname in f:
        p = os.path.abspath(custom_path + fname)
        if os.path.isfile(p):
            n = pretty_name(os.path.basename(p))
            deployscripts[n] = p

    db.session.query(DeployScript).delete()
    for honeypot, deploypath in sorted(deployscripts.items()):
        with open(deploypath, 'r') as deployfile:
            initdeploy = DeployScript()
            initdeploy.script = deployfile.read()
            initdeploy.notes = 'Vanilla deploy script for {}'.format(honeypot)
            initdeploy.user = superuser
            initdeploy.name = honeypot
            db.session.add(initdeploy)
            db.session.commit()
