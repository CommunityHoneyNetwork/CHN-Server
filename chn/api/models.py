import string
from random import choice
from datetime import datetime

from sqlalchemy import UniqueConstraint, func

from chn import db
from chn.api import APIModel
from chn.auth.models import User
from chn.common.clio import Clio


class Sensor(db.Model, APIModel):

    # Defines some properties on the fields:
    # required: Is required for creating object via
    #           a POST request.
    # editable: Can be edited via a PUT request.
    all_fields = {
        'uuid': {'required': False, 'editable': False},
        'name': {'required': True, 'editable': True},
        'created_date': {'required': False, 'editable': False},
        'ip': {'required': False, 'editable': True},
        'hostname': {'required': True, 'editable': True},
        'honeypot': {'required': True, 'editable': False}
    }

    __tablename__ = 'sensors'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True)
    name = db.Column(db.String(50))
    created_date = db.Column(
            db.DateTime(), default=datetime.utcnow)
    ip = db.Column(db.String(15))
    hostname = db.Column(db.String(50))
    identifier = db.Column(db.String(50), unique=True)
    honeypot = db.Column(db.String(50))

    def __init__(
          self, uuid=None, name=None, created_date=None, honeypot=None,
          ip=None, hostname=None, identifier=None, **args):
        self.uuid = uuid
        self.name = name
        self.created_date = created_date
        self.ip = ip
        self.hostname = hostname
        self.identifier = identifier
        self.honeypot = honeypot

    def __repr__(self):
        return '<Sensor>{}'.format(self.to_dict())

    def to_dict(self):
        return dict(
            uuid=self.uuid, name=self.name, honeypot=self.honeypot,
            created_date=str(self.created_date), ip=self.ip,
            hostname=self.hostname, identifier=self.uuid,
            # Extending with info from Mnemosyne.
            secret=self.authkey.secret, publish=self.authkey.publish)

    def new_auth_dict(self):
        el = string.ascii_letters + string.digits
        rand_str = lambda n: ''.join(choice(el) for _ in range(n))
        return dict(secret=rand_str(16), owner="chn",
                    identifier=self.uuid, honeypot=self.honeypot,
                    subscribe=[], publish=Sensor.get_channels(self.honeypot))

    @property
    def attacks_count(self):
        return Clio().counts.get_count(identifier=self.uuid)

    @property
    def authkey(self):
        return Clio().authkey.get(identifier=self.uuid)

    @staticmethod
    def get_channels(honeypot):
        from chn import chn
        return chn.config.get('HONEYPOT_CHANNELS', {}).get(honeypot, [])


class DeployScript(db.Model, APIModel):
    all_fields = {
        'script': {'required': True, 'editable': True},
        'name': {'required': True, 'editable': True},
        'date': {'required': False, 'editable': False},
        'notes': {'required': True, 'editable': True},
    }

    __tablename__ = 'deploy_scripts'

    id = db.Column(db.Integer, primary_key=True)
    script = db.Column(db.String(102400))
    date = db.Column(
             db.DateTime(), default=datetime.utcnow)
    notes = db.Column(db.String(140))
    name = db.Column(db.String(140))
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User, uselist=False)

    def __init__(self, name=None, script=None, notes=None):
        self.name = name
        self.script = script
        self.notes = notes

    def __repr__(self):
        return '<DeployScript>{}'.format(self.to_dict())

    def to_dict(self):
        return dict(script=self.script, date=self.date, notes=self.notes,
                    user=self.user.email, id=self.id)
