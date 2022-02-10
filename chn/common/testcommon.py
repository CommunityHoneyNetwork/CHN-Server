import os
import json

from flask import url_for
from flask.ext.testing import TestCase
import pymongo

import chn.common.clio as clio
from chn import create_clean_db, chn, db

import config

# Patching clio to use different database than production.
clio_res = (clio.AuthKey, clio.ResourceMixin,)
for res in clio_res:
    res.db_name = 'test_{}'.format(res.db_name)
# End patching.


class CHNTestCase(TestCase):

    def __init__(self, *args, **kwargs):
        super(CHNTestCase, self).__init__(*args, **kwargs)
        self.clio = clio.Clio()

    def create_app(self):
        _basedir = os.path.abspath(os.path.dirname(__file__))
        db_uri = 'sqlite:///' + os.path.join(_basedir, 'test-chn.db')
        chn.config['SQLALCHEMY_DATABASE_URI'] = db_uri
        chn.config['TESTING'] = True
        return chn

    def setUp(self):
        create_clean_db()
        self.email = self.app.config['SUPERUSER_EMAIL']
        self.passwd = self.app.config['SUPERUSER_ONETIME_PASSWORD']

    def tearDown(self):
        db.session.remove()
        db.drop_all()

        # Removing test collections from mongo.
        cli = pymongo.MongoClient(host=config.MONGODB_HOST,
                                  port=config.MONGODB_PORT)
        for dbname in cli.database_names():
            if dbname.startswith('test_'):
                cli.drop_database(dbname)

    def login(self, email=None, password=None):
        if email is None:
            email = self.email
        if password is None:
            password = self.passwd
        login_url = url_for('auth.login_user')
        logindata = json.dumps(dict(email=email, password=password))
        self.client.post(login_url, data=logindata, content_type='application/json')
