from datetime import datetime

from flask_security import UserMixin, RoleMixin
from flask import render_template, g, current_app as mhn

from mhn import db
from mhn.api import APIModel

roles_users = db.Table('roles_users',
    db.Column('id', db.Integer(), primary_key=True),
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE')))



class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), nullable=False, server_default=u'', unique=True) # for @roles_accepted()
    description = db.Column(db.String(255), server_default=u'') # for display purposes


class User(db.Model, APIModel, UserMixin):
    all_fields = {
        'email': {'required': True, 'editable': False},
        'password': {'required': True, 'editable': True},
        'active': {'required': False, 'editable': True},
        'from_ldap': {'required': False, 'editable': False}
    }

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    from_ldap = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    
    def to_dict(self):
        return dict(
                email=self.email, roles=[r.name for r in self.roles],
                active=self.active)

    def has_role(self, role, allow_admin=True):
        if self.password == 'LDAP':
            from mhn.auth.views import ldap_user_to_role
            mhn.logger.debug('Checking if user "%s" is a member of the ldap group mapped to role "%s"' % (self.email, role) )
            user_current_ldap_group_to_role = ldap_user_to_role(self.email)
            if user_current_ldap_group_to_role == role:
                return True
            else:
                if user_current_ldap_group_to_role:
                    from mhn.auth.views import create_or_update_ldap_user
                    #if role == 'admin' and role in current_user.roles:
                    # TODO: i'm not currently aware of a way to do this in flask-security
                    # if we got here, the user's session has admin but ldap groups have changed since
                    # logon, so remove admin from session role
                    # 
                    user = create_or_update_ldap_user(self, user_current_ldap_group_to_role)
                return False

        for item in self.roles:
            if item.name == role:
                return True
            if allow_admin and item.name == 'admin':
                return True
        return False

    def get_role_from_ldap_group(self):
        for role in (r.name for r in db.session.query(Role).all()):
            if self.has_role(role):
                mhn.logger.debug('Logging in user %s with role %s' % (self.email, role))
                return role
        mhn.logger.debug('User %s successfully authed but had no appropiate ldap groups' % (self.email))
        return False

    def role(self):
        for item in self.roles:
            return item.name

    def name(self):
        return self.first_name + " " + self.last_name


class PasswdReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hashstr = db.Column(db.String(40))
    created = db.Column(db.DateTime(), default=datetime.utcnow)
    active = db.Column(db.Boolean())
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User, uselist=False)

    @property
    def email_body(self):
        from mhn import mhn
        return render_template(
                'auth/reset-email.html', hashstr=self.hashstr,
                 server_url=mhn.config['SERVER_BASE_URL'],
                 email=self.user.email)

class ApiKey(db.Model):
    all_fields = {
        'api_key': {'required': True, 'editable': False},
        'user_id': {'required': True, 'editable': False}
    }

    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(32), unique=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
