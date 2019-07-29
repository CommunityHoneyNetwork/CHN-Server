import datetime

import random
import hashlib

from flask import Blueprint, request, jsonify, current_app as mhn
from flask import current_app as app
from flask_mail import Message
from sqlalchemy.exc import IntegrityError
from flask_security.utils import (
        login_user as login, verify_and_update_password,
        encrypt_password, logout_user as logout)

from flask_ldap3_login import AuthenticationResponseStatus

from mhn import ldap3_manager, db, mail, mhn
from mhn import user_datastore
from mhn.common.utils import error_response
from mhn.auth.models import User, Role, PasswdReset, ApiKey
from mhn.auth import errors
from mhn.auth import (
    get_datastore, login_required, roles_accepted, current_user)
from mhn.api import errors as apierrors
import uuid

auth = Blueprint('auth', __name__, url_prefix='/auth')

@auth.route('/login/', methods=['POST'])
def login_user():
    if 'email' not in request.json:
        return error_response(errors.AUTH_EMAIL_MISSING, 400)
    if 'password' not in request.json:
        return error_response(errors.AUTH_PSSWD_MISSING, 400)
    # email and password are in the posted data.
    email = request.json.get('email')
    user = User.query.filter_by(
            email=email).first()
    if mhn.config.get('LDAP_AUTH_ENABLED', False):
        ldap_attempt = do_ldap_authentication(email, request.json.get('password'))
        if ldap_attempt:
            return ldap_attempt
    psswd_check = False
    if user:
        psswd_check = verify_and_update_password(
                request.json.get('password'), user)
    if user and psswd_check:
        login(user, remember=True)
        return jsonify(user.to_dict())
    else:
        return error_response(errors.AUTH_INCORRECT_CREDENTIALS, 401)


@auth.route('/logout/', methods=['GET'])
def logout_user():
    logout()
    return jsonify({})


@auth.route('/user/', methods=['POST'])
@auth.route('/register/', methods=['POST'])
@roles_accepted('admin')
def create_user():
    missing = User.check_required(request.json)
    if missing:
        return error_response(
                apierrors.API_FIELDS_MISSING.format(missing), 400)
    else:
        user = get_datastore().create_user(
                email=request.json.get('email'),
                password=encrypt_password(request.json.get('password'))
                )
        userrole = request.json.get('role')
        user_datastore.add_role_to_user(user, userrole)

        try:
            db.session.add(user)
            db.session.flush()

            apikey = ApiKey(user_id=user.id, api_key=str(uuid.uuid4()).replace("-", ""))
            db.session.add(apikey)

            db.session.commit()
        except IntegrityError:
            return error_response(errors.AUTH_USERNAME_EXISTS, 400)
        else:
            return jsonify(user.to_dict())


@auth.route('/user/<user_id>/', methods=['DELETE'])
@roles_accepted('admin')
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return error_response(errors.AUTH_NOT_FOUND.format(user_id), 404)
    user.active= False
    db.session.add(user)
    db.session.delete(user)
    db.session.commit()
    return jsonify({})


@auth.route('/resetrequest/', methods=['POST'])
def reset_passwd_request():
    if 'email' not in request.json:
        return error_response(errors.AUTH_EMAIL_MISSING, 400)
    email = request.json['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        return error_response(errors.AUTH_NOT_FOUND.format(email), 404)
    hashstr = hashlib.sha1(str(random.getrandbits(128)) + user.email).hexdigest()
    # Deactivate all other password resets for this user.
    PasswdReset.query.filter_by(user=user).update({'active': False})
    reset = PasswdReset(hashstr=hashstr, active=True, user=user)
    db.session.add(reset)
    db.session.commit()
    # Send password reset email to user.
    msg = Message(
            html=reset.email_body, subject='MHN Password reset',
            recipients=[user.email], sender=mhn.config['DEFAULT_MAIL_SENDER'])
    try:
        mail.send(msg)
    except:
        return error_response(errors.AUTH_SMTP_ERROR, 500)
    else:
        return jsonify({})


@auth.route('/changepass/', methods=['POST'])
def change_passwd():
    password = request.json.get('password')
    password_repeat = request.json.get('password_repeat')
    if not password or not password_repeat:
        # Request body is not complete.
        return error_response(errors.AUTH_RESET_MISSING, 400)
    if password != password_repeat:
        # Password do not match.
        return error_response(errors.AUTH_PASSWD_MATCH, 400)
    if current_user.is_authenticated:
        # No need to check password hash object or email.
        user = current_user
    else:
        email = request.json.get('email')
        hashstr = request.json.get('hashstr')
        if not email or not hashstr:
            # Request body is not complete for not authenticated
            # request, ie, uses password reset hash.
            return error_response(errors.AUTH_RESET_MISSING, 400)
        reset = db.session.query(PasswdReset).join(User).\
                    filter(User.email == email, PasswdReset.active == True).\
                    filter(PasswdReset.hashstr == hashstr).\
                    first()
        if not reset:
            return error_response(errors.AUTH_RESET_HASH, 404)
        db.session.add(reset)
        reset.active = False
        user = reset.user
    user.password = encrypt_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({})


@auth.route('/me/', methods=['GET'])
@login_required
def get_user():
    return jsonify(current_user.to_dict())

# supporting functions
def do_ldap_authentication(username, password):
    """Auth users against LDAP server
    :param username: ldap email or username
    :param password: account password

    :return bool: 
        False: if auth fails or user not in appropriate ldap groups
        flask.Response() containing User record: if successful auth and user in appropriate ldap group(s)
    """
    if '@' in username:
        ldap_user = username.split('@')[0]
    elif '\\' in username:
        ldap_user = username.split('\\')[1]
    else:
        ldap_user = username
    ldap_info, ldap_authenticated = _ldap_authenticate(ldap_user, password)
    # ldap_info (on success) is object w/ properties: user_info, user_id, user_dn, user_groups

    if ldap_authenticated:
        # ldap_info.user_groups contains ldap groups of the user_dn, however, not all ldap
        # implementations use the full user_dn for group membership - some only use username
        # as a result, get the groups through a custom function that checks both
        user_groups = get_ldap_groups_for_user(ldap_user)
        if user_groups:
            role = _authorized_ldap_group_to_role(user_groups)
            if role:
                login_attr = mhn.config.get('LDAP_USER_LOGIN_ATTR')
                username = ldap_info.user_info[login_attr]
                # some ldap directories return a list of users with just one item in the list
                # if that happens, select the first item as the username
                if str(type(username)) == "<type 'list'>":
                    username = username[0]
                user = User.query.filter_by(email=username).first()
                if not user:
                    user = User(email=username,
                        active=True,
                        confirmed_at=datetime.datetime.utcnow(),
                        from_ldap=True, password='LDAP')
                user = create_or_update_ldap_user(user, role)
                app.logger.debug('Logging in ldap user "%s" with role "%s"' % (username, role)) 
                if login(user, remember=True):
                    return jsonify(user.to_dict())

    return False

def _ldap_authenticate(username, password):
    """Performs a search bind to auth a user
    :param username: LDAP username
    :param password: account password
    :return: Returns a tuple of user_info and authentication status
    :rtype: tuple
    """
    user = None
    authenticated = False

    ldap_auth = ldap3_manager.authenticate_search_bind(username, password)
    if ldap_auth.status is AuthenticationResponseStatus.success:
        user = ldap_auth
        authenticated = True

    return user, authenticated


def create_or_update_ldap_user(user, role):
    """Given User obj and an app role, save the user to db if they don't yet exist,
    or update their role if they do already
    :param user: app User model object
    :param role: role ('admin' or 'user') to give user in application
    :return user (obj): if successful, return the User model user object
    """
    if not user:
        user = User(email=username,
                active=True,
                confirmed_at=datetime.datetime.utcnow(),
                from_ldap=True, password='LDAP')
    app_roles = (r.name for r in db.session.query(Role).all())
    for app_role in app_roles:
        if app_role != role:
            app.logger.debug('Removing role %s from user %s' % (app_role, user.email))
            user_datastore.remove_role_from_user(user, app_role)
    user_datastore.add_role_to_user(user, role)
    try:
        db.session.add(user)
        db.session.flush()
        db.session.commit()
    except IntegrityError:
        raise error_response(errors.AUTH_USERNAME_EXISTS, 400)
    return user

def _authorized_ldap_group_to_role(user_groups):
    """Determine whether user is in one of the LDAP groups from config that authorizes use of web app
    :param user_groups: user_groups dictionary as returned from ldap server via ldap3_manager
    :return bool:
        False: if user not in an authorized ldap group
        Role: if user is in one of the groups, return the corresponding app role
    """
    roles = (r.name for r in db.session.query(Role).all())
    for group in user_groups:
        for role in roles:
            authorized_group = mhn.config.get('LDAP_GROUP_TO_ROLE_%s' % role.upper(), False)
            if not authorized_group:
                continue
            app.logger.debug('Checking if user is a member of ldap group %s' % (authorized_group) )
            if authorized_group in group[mhn.config.get('LDAP_USER_RDN_ATTR', 'cn')]:
                app.logger.debug('User role mapped to "%s" based on membership in ldap group "%s"' % (role, group[mhn.config.get('LDAP_USER_RDN_ATTR', 'cn')]))
                return role
    app.logger.debug('No authorized ldap group found')
    return False

def ldap_user_to_role(user):
    """Take an ldap user and return their properly mapped app role (if any)
    :param user: ldap username (uid or sAMAccountName, not full email)
    :return bool:
        False: if user has no found, mapped role authorized for app use
        Role: if user is a member of an ldap group that's successfully mapped to an app role, return the role
    """
    user_groups = get_ldap_groups_for_user(user)
    if not user_groups:
        return False
    role = _authorized_ldap_group_to_role(user_groups)
    if not role:
        app.logger.debug('No app roles found based on user %s ldap groups' % user)
        return False
    return role


def ldap_user_has_role(user, role):
    """Determines if a user should have a certain app role
    :param user: ldap username
    :param role: app role ('admin' or 'user')
    :return bool:
        True: if user has group for that role, return true
        False: return false if user doesn't have ldap group translating to that role
    """
    app.logger.debug('Translating user ldap groups for %s to determine if they have %s role' % (user, role) )
    user_groups = get_ldap_groups_for_user(user)
    if not user_groups:
        return False
    for group in user_groups:
        authorized_group = mhn.config.get('LDAP_GROUP_TO_ROLE_%s' % role.upper(), False)
        app.logger.debug('Checking if user is a member of ldap group %s' % (authorized_group) )
        if authorized_group == group[mhn.config.get('LDAP_USER_RDN_ATTR', 'cn')]:
            app.logger.debug('User role mapped to "%s" based on membership in ldap group "%s"' % (role, group[mhn.config.get('LDAP_USER_RDN_ATTR', 'cn')]))
            return True

    return False

def get_ldap_groups_for_user(username):
    """Given ldap username, return ldap groups by trying group search from user_dn and username
    :param username: ldap username
    :return bool: 
        list: A list of LDAP groups the user is a member of, if found
        False: bool False if no ldap groups are found or if user is not found
    """
    user_info = ldap3_manager.get_user_info_for_username(username)
    if not user_info:
        app.logger.debug('No user info found for %s.' % username)
        return False
    ldap_groups_for_user = ldap3_manager.get_user_groups(user_info['dn'])
    if not ldap_groups_for_user:
        app.logger.debug('No user groups found for user %s under dn %s. Trying username search rather than user_dn...' % (username, user_info['dn']))
        ldap_groups_for_user = ldap3_manager.get_user_groups(username)
        if not ldap_groups_for_user:
            app.logger.debug('No user groups found for user %s after username search either.' % username)
            # if we get here, user has no groups, so if they're logged in, log them out
            # e.g., if their ldap groups were removed while they had a logged in session
            logout()
            return False
    app.logger.debug('Found ldap groups for user %s' % username)
    return ldap_groups_for_user
