"""
This is a helper script meant to generate a
working config.py file from the config template.
"""

from getpass import getpass
import json
import os.path
from random import choice
import string
import sys
from urllib2 import urlopen

import argparse


el = string.ascii_letters + string.digits
rand_str = lambda n: ''.join(choice(el) for _ in range(n))


def generate_config():
    # Check if config file already exists
    if os.path.isfile('config.py'):
        print('config.py already exists')
        sys.exit()

    pub_ip = json.load(urlopen('http://httpbin.org/ip'))['origin']
    # edge case where httpbin can return a list of comma-separated, external ips
    # if that happens, split by comma and deep-six everything after the first ip
    pub_ip = pub_ip.split(',', 1)[0]
    default_base_url = 'http://{}'.format(pub_ip)
    default_honeymap_url = '{}:3000'.format(default_base_url)
    default_redis_url = 'redis://localhost:6379'
    default_log_path = '/var/log/mhn/mhn.log'
    default_superuser_password = rand_str(32)
    default_secret_key = rand_str(32)
    default_deploy_key = rand_str(8)
    localconfig = dict()

    is_unattended = False

    # Get and parse args for command unattended install
    parser_description = 'This is a help script to generate a working config.py file from the config template.'
    parser = argparse.ArgumentParser(description=parser_description)

    subparsers = parser.add_subparsers(help='commands')

    parser_generate = subparsers.add_parser('generate', help='Generate a config.py and prompt for options')
    parser_generate.set_defaults(which='generate')

    parser_unatt = subparsers.add_parser('unattended', help='Unattended install')
    parser_unatt.set_defaults(which='unattended')
    parser_unatt.add_argument('-e', '--email', type=str, required=True,
                              help='Superuser email address')
    parser_unatt.add_argument('-p', '--password', type=str,
                              help='Superuser password')
    parser_unatt.add_argument('-b', '--base_url', type=str, default=default_base_url,
                              help='Server base url')
    parser_unatt.add_argument('-y', '--honeymap_url', type=str, default=default_honeymap_url,
                              help='Honeymap url')
    parser_unatt.add_argument('-r', '--redis_url', type=str, default=default_redis_url,
                              help='Redis url')
    parser_unatt.add_argument('-m', '--mail_server', type=str, default='localhost',
                              help='Mail server address')
    parser_unatt.add_argument('-s', '--mail_port', type=int, default=25,
                              help='Mail server port')
    parser_unatt.add_argument('--mail_tls', action='store_true',
                              help='Use TLS for mail')
    parser_unatt.add_argument('--mail_ssl', action='store_true',
                              help='Use SSL for mail')
    parser_unatt.add_argument('--mail_user', type=str, default='',
                              help='Mail username')
    parser_unatt.add_argument('--mail_pass', type=str, default='',
                              help='Mail password')
    parser_unatt.add_argument('--mail_sender', type=str, default='',
                              help='Mail sender')
    parser_unatt.add_argument('-l', '--log_file_path', type=str, default=default_log_path,
                              help='Log file path')
    parser_unatt.add_argument('-d', '--debug', action='store_true',
                              help='Run in debug mode')
    parser_unatt.add_argument('--mongo_host', type=str, default="localhost",
                              help='MongoDB address')
    parser_unatt.add_argument('--mongo_port', type=int, default=27017,
                              help='MongoDB port')
    parser_unatt.add_argument('--hpfeeds_host', type=str, default="localhost",
                              help='HPFeeds address')
    parser_unatt.add_argument('--hpfeeds_port', type=int, default=10000,
                              help='HPFeeds port')
    parser_unatt.add_argument('--secret_key', type=str,
                              help='CHN Server secret key')
    parser_unatt.add_argument('--deploy_key', type=str,
                              help='CHN Server honeypot deploy key')
    parser_unatt.add_argument('--ldap_auth', action='store_true',
                              help='Allow LDAP login for usernames')
    parser_unatt.add_argument('--ldap_host', type=str,
                              help='Hostname or IP for ldap server')
    parser_unatt.add_argument('--ldap_port', type=int, default=389,
                              help='Port over which to contact ldap server')
    parser_unatt.add_argument('--ldap_ssl', action='store_true',
                              help='Use SSL for ldap binds')
    parser_unatt.add_argument('--ldap_ssl_validate', type=str, default='CERT_NONE',
                              help='CERT_REQUIRED (required and validated) | CERT_OPTIONAL (not required, but validated if provided) | CERT_NONE (certs are ignored)')
    parser_unatt.add_argument('--ldap_ssl_cert_file', type=str, default='/etc/letsencrypt/ldaps/cert.cer',
                              help='Path to CA cert file for ldaps, e.g., /path/to/cert.cer')
    parser_unatt.add_argument('--ldap_ssl_protocol_version', type=str, default='TLS',
                              help='SSL or TLS version to use: TLSv1_2 | TLSv1_1 | TLSv1 | TLS (i.e., SSLv23) | SSLv3 | SSLv2')
    parser_unatt.add_argument('--ldap_bind_user', type=str,
                              help='Full DN of service account used to auth ldap server')
    parser_unatt.add_argument('--ldap_bind_password', type=str,
                              help='Password for ldap bind user')
    parser_unatt.add_argument('--ldap_base_dn', type=str,
                              help='Base DN from where all users and groups will be searched')
    parser_unatt.add_argument('--ldap_user_dn', type=str,
                              help='DN of OU containing ldap users to be prepended to base_dn')
    parser_unatt.add_argument('--ldap_user_search_scope', type=str,
                              help='Scope to search for users; "LEVEL" for user_dn root; "SUBTREE" for recursive search under user_dn')
    parser_unatt.add_argument('--ldap_user_class', type=str,
                              help='Ldap user object class; inetOrgPerson for OpenLDAP; person for MSAD')
    parser_unatt.add_argument('--ldap_user_login_attribute', type=str,
                              help='What corresponds to username for ldap; uid for OpenLDAP; sAMAccountName for MSAD')
    parser_unatt.add_argument('--ldap_user_rdn_attribute', type=str,
                              help='Specifies RDN attribute used in ldap; uid for OpenLDAP; sAMAccountName for MSAD')
    parser_unatt.add_argument('--ldap_group_dn', type=str,
                              help='DN of OU containing ldap groups to be prepended to base_dn')
    parser_unatt.add_argument('--ldap_group_search_scope', type=str,
                              help='Scope to search for groups; "LEVEL" for group_dn root; "SUBTREE" for recursive search under group_dn')
    parser_unatt.add_argument('--ldap_group_attribute', type=str,
                              help='Group member attribute for ldap; memberUid for OpenLDAP; member for MSAD')
    parser_unatt.add_argument('--ldap_group_class', type=str,
                              help='Ldap group object class; posixGroup for OpenLDAP; group for MSAD')
    parser_unatt.add_argument('--ldap_group_admins', type=str,
                              help='Name of ldap group containing admin users')
    parser_unatt.add_argument('--ldap_group_users', type=str,
                              help='Name of ldap group containing standard users')

    if (len(sys.argv) < 2):
        args = parser.parse_args(['generate'])
    else:
        args = parser.parse_args(sys.argv[1:])

    # check for unattended install
    if args.which is 'unattended':
        is_unattended = True

    if is_unattended:
        # Collect values from arguments
        debug = args.debug
        email = args.email
        password = args.password
        server_base_url = args.base_url
        honeymap_url = args.honeymap_url
        redis_url = args.redis_url
        mail_server = args.mail_server
        mail_port = args.mail_port
        mail_tls = args.mail_tls
        mail_ssl = args.mail_ssl
        mail_username = args.mail_user
        mail_password = args.mail_pass
        default_mail_sender = args.mail_sender
        log_file_path = args.log_file_path
        mongo_host = args.mongo_host
        mongo_port = args.mongo_port
        hpfeeds_host = args.hpfeeds_host
        hpfeeds_port = args.hpfeeds_port
        secret_key = args.secret_key
        deploy_key = args.deploy_key
        ldap_auth = args.ldap_auth
        ldap_host = args.ldap_host
        ldap_port = args.ldap_port
        ldap_ssl = args.ldap_ssl
        ldap_ssl_validate = args.ldap_ssl_validate
        ldap_ssl_cert_file = args.ldap_ssl_cert_file
        ldap_ssl_protocol_version = args.ldap_ssl_protocol_version
        ldap_bind_user = args.ldap_bind_user
        ldap_bind_password = args.ldap_bind_password
        ldap_base_dn = args.ldap_base_dn
        ldap_user_dn = args.ldap_user_dn
        ldap_user_search_scope = args.ldap_user_search_scope
        ldap_user_class = args.ldap_user_class
        ldap_user_login_attribute = args.ldap_user_login_attribute
        ldap_user_rdn_attribute = args.ldap_user_rdn_attribute
        ldap_group_dn = args.ldap_group_dn
        ldap_group_search_scope = args.ldap_group_search_scope
        ldap_group_attribute = args.ldap_group_attribute
        ldap_group_class = args.ldap_group_class
        ldap_group_admins = args.ldap_group_admins
        ldap_group_users = args.ldap_group_users
    else:
        # Collect values from user
        debug = raw_input('Do you wish to run in Debug mode?: y/n ')
        while debug not in ['y', 'n']:
            debug = raw_input('Please y or n ')
        debug = True if debug == 'y' else False

        email = raw_input('Superuser email: ')
        while '@' not in email:
            email = raw_input('Superuser email (must be valid): ')

        while True:
            password = getpass('Superuser password: ')
            while not password:
                password = getpass('Superuser password (cannot be blank): ')

            password2 = getpass('Superuser password: (again): ')
            while not password2:
                password2 = getpass('Superuser password (again; cannot be blank): ')

            if password == password2:
                break
            else:
                print "Passwords did not match. Try again"

        secret_key = raw_input('CHN Server secret key [""]: ')
        deploy_key = raw_input('CHN Server honeypot deployment key [""]: ')

        server_base_url = raw_input('Server base url ["{}"]: '.format(default_base_url))
        if server_base_url.endswith('/'):
            server_base_url = server_base_url[:-1]

        default_honeymap_url = '{}:3000'.format(server_base_url)
        honeymap_url = raw_input('Honeymap url ["{}"]: '.format(default_honeymap_url))
        if honeymap_url.endswith('/'):
            honeymap_url = honeymap_url[:-1]

        default_redis_url = 'redis://localhost:6379'
        redis_url = raw_input('Redis url ["{}"]: '.format(default_redis_url))
        if redis_url.endswith('/'):
            redis_url = redis_url[:-1]

        mail_server = raw_input('Mail server address ["localhost"]: ')
        mail_port = raw_input('Mail server port [25]: ')

        mail_tls = raw_input('Use TLS for email?: y/n ')
        while mail_tls not in ['y', 'n']:
            mail_tls = raw_input('Please y or n ')

        mail_ssl = raw_input('Use SSL for email?: y/n ')
        while mail_ssl not in ['y', 'n']:
            mail_ssl = raw_input('Please y or n ')

        mail_username = raw_input('Mail server username [""]: ')
        mail_password = getpass('Mail server password [""]: ')

        default_mail_sender = raw_input('Mail default sender [""]: ')

        log_file_path = raw_input('Path for log file ["{}"]: '.format(default_log_path))

        mongo_host = raw_input('MongoDB hostname ["localhost"]: ')
        mongo_port = raw_input('MongoDB port[27017]: ')
        hpfeeds_host = raw_input('HPFeeds hostname ["localhost"]: ')
        hpfeeds_port = raw_input('HPFeeds port[10000]: ')

        ldap_auth = raw_input('Allow LDAP for user login?: y/n ')
        while ldap_auth not in ['y', 'n']:
            ldap_auth = raw_input('Please y or n ')
        ldap_auth = True if ldap_auth == 'y' else False
        
        if ldap_auth:
            ldap_host = raw_input('LDAP server hostname/IP ["localhost"]: ')
            ldap_port = raw_input('LDAP port[389]: ')
            
            ldap_ssl = raw_input('Use SSL for LDAP binds?: y/n ')
            while ldap_ssl not in ['y', 'n']:
                ldap_ssl = raw_input('Please y or n ')
            ldap_ssl = True if ldap_ssl == 'y' else False
            if ldap_ssl:
                ldap_ssl_validate = raw_input('SSL Cert Validation: [CERT_REQUIRED] (required & validated); [CERT_OPTIONAL] (not required, but validated if provided); [CERT_NONE] (certs are ignored) ')
                while ldap_ssl_validate not in ['CERT_REQUIRED', 'CERT_OPTIONAL', 'CERT_NONE']:
                    ldap_ssl_validate = raw_input('Please CERT_REQUIRED | CERT_OPTIONAL | CERT_NONE ')
                ldap_ssl_cert_file = raw_input('Path for CA cert file ["/path/to/cert.cer"]: ')
                ldap_ssl_protocol_version = raw_input('SSL/TLS Protocol Version: TLSv1_2 | TLSv1_1 | TLSv1 | TLS (i.e. SSLv23 - Selects highest protocol version supported by both client/server ) | SSLv3 | SSLv2 ')
                while ldap_ssl_protocol_version not in ['TLSv1_2', 'TLSv1_1', 'TLSv1', 'TLS', 'SSLv23', 'SSLv3', 'SSLv2']:
                    ldap_ssl_protocol_version = raw_input('Please TLSv1_2 | TLSv1_1 | TLSv1 | TLS | SSLv3 | SSLv2 ')

            ldap_bind_user = raw_input('Full DN of svc acct for authing to ldap ["cn=svc_ldap,dc=domain,dc=local"]: ')
            while True:
                ldap_bind_password = getpass('Ldap service account password: ')
                ldap_bind_password2 = getpass('Ldap service account password: (again): ')
                if ldap_bind_password == ldap_bind_password2:
                    break
                else:
                    print "Passwords did not match. Try again"
            ldap_base_dn = raw_input('Full DN of domain base ["dc=domain,dc=local"]: ')
            ldap_user_dn = raw_input('Base OU containing ldap users to be prepended to base_dn ["ou=users"]: ')
            ldap_user_search_scope = raw_input('Search scope when looking for users ["LEVEL" (user_dn root only) / "SUBTREE" (user_dn and recursive OUs beneath)]: ')
            ldap_user_class = raw_input('LDAP user objectClass ["inetOrgPerson" (OpenLDAP) / "person" (MSAD)]: ')
            ldap_user_login_attribute = raw_input('LDAP user login attribute ["uid" (OpenLDAP) / "sAMAccountName" (MSAD)]: ')
            ldap_user_rdn_attribute = raw_input('RDN attribute for LDAP users ["uid" (OpenLDAP) / "sAMAccountName" (MSAD)]: ')
            ldap_group_dn = raw_input('Base OU containing ldap groups to be prepended to base_dn ["ou=groups"]: ')
            ldap_group_search_scope = raw_input('Search scope when looking for groups ["LEVEL" (group_dn root only) / "SUBTREE" (group_dn and recursive OUs beneath)]: ')

            ldap_group_class = raw_input('LDAP group objectClass ["posixGroup" (OpenLDAP) / "group" (MSAD)]: ')
            ldap_group_admins = raw_input('Name of LDAP group to map to application admins ["sg-chn-admins"]: ')
            ldap_group_users = raw_input('Name of LDAP group to map to application users ["sg-chn-users"]: ')

    server_base_url = server_base_url if server_base_url.strip() else default_base_url
    honeymap_url = honeymap_url if honeymap_url.strip() else default_honeymap_url
    redis_url = redis_url if redis_url.strip() else default_redis_url
    log_file_path = log_file_path if log_file_path else default_log_path
    password = password if password else default_superuser_password
    secret_key = secret_key if secret_key else default_secret_key
    deploy_key = deploy_key if deploy_key else default_deploy_key
    # instruct Flask-LDAP3-Login to not automatically add server if we're using SSL for LDAP
    # this is b/c we'll be setting up a custom Tls context later
    ldap_add_server = False if ldap_ssl else True

    localconfig['DEBUG'] = debug
    localconfig['SUPERUSER_EMAIL'] = email
    localconfig['SUPERUSER_ONETIME_PASSWORD'] = password
    localconfig['SECRET_KEY'] = secret_key
    localconfig['DEPLOY_KEY'] = deploy_key
    localconfig['SERVER_BASE_URL'] = server_base_url
    localconfig['HONEYMAP_URL'] = honeymap_url
    localconfig['REDIS_URL'] = redis_url
    localconfig['MAIL_SERVER'] = mail_server if mail_server else "localhost"
    localconfig['MAIL_PORT'] = mail_port if mail_port else 25
    localconfig['MAIL_USE_TLS'] = 'y' == mail_tls
    localconfig['MAIL_USE_SSL'] = 'y' == mail_ssl
    localconfig['MAIL_USERNAME'] = mail_username if mail_username else ''
    localconfig['MAIL_PASSWORD'] = mail_password if mail_password else ''
    localconfig['DEFAULT_MAIL_SENDER'] = default_mail_sender if default_mail_sender else ""
    localconfig['LOG_FILE_PATH'] = log_file_path
    localconfig['MONGODB_HOST'] = mongo_host if mongo_host else "localhost"
    localconfig['MONGODB_PORT'] = mongo_port if mongo_port else 27017
    localconfig['HPFEEDS_HOST'] = hpfeeds_host if hpfeeds_host else "localhost"
    localconfig['HPFEEDS_PORT'] = hpfeeds_port if hpfeeds_port else 10000
    localconfig['LDAP_AUTH_ENABLED'] = ldap_auth if ldap_auth else False
    localconfig['LDAP_HOST'] = ldap_host if ldap_host else ''
    localconfig['LDAP_PORT'] = ldap_port if ldap_port else 389
    localconfig['LDAP_USE_SSL'] = ldap_ssl if ldap_ssl else False
    localconfig['LDAP_SSL_VALIDATE'] = ldap_ssl_validate if ldap_ssl_validate else 'CERT_NONE'
    localconfig['LDAP_SSL_CERT_FILE'] = ldap_ssl_cert_file if ldap_ssl_cert_file else '/path/to/cert.cer'
    localconfig['LDAP_SSL_PROTOCOL_VERSION'] = ldap_ssl_protocol_version if ldap_ssl_protocol_version else 'TLS'
    localconfig['LDAP_ADD_SERVER'] = ldap_add_server 
    localconfig['LDAP_BIND_USER_DN'] = ldap_bind_user if ldap_bind_user else 'cn=svc_acct,dc=domain,dc=com'
    localconfig['LDAP_BIND_USER_PASSWORD'] = ldap_bind_password if ldap_bind_password else 'mysecret'
    localconfig['LDAP_BASE_DN'] = ldap_base_dn if ldap_base_dn else 'dc=domain,dc=com'
    localconfig['LDAP_USER_DN'] = ldap_user_dn if ldap_user_dn else 'ou=users'
    localconfig['LDAP_USER_SEARCH_SCOPE'] = ldap_user_search_scope if ldap_user_search_scope else 'SUBTREE'
    localconfig['LDAP_USER_OBJECT_CLASS'] = ldap_user_class if ldap_user_class else 'user'
    localconfig['LDAP_USER_LOGIN_ATTR'] = ldap_user_login_attribute if ldap_user_login_attribute else 'sAMAccountName'
    localconfig['LDAP_USER_RDN_ATTR'] = ldap_user_rdn_attribute if ldap_user_rdn_attribute else 'sAMAccountName'
    localconfig['LDAP_GROUP_DN'] = ldap_group_dn if ldap_group_dn else 'ou=groups'
    localconfig['LDAP_GROUP_SEARCH_SCOPE'] = ldap_group_search_scope if ldap_group_search_scope else 'SUBTREE'
    localconfig['LDAP_GROUP_MEMBERS_ATTR'] = ldap_group_attribute if ldap_group_attribute else 'member'
    localconfig['LDAP_GROUP_OBJECT_CLASS'] = ldap_group_class if ldap_group_class else 'group'
    localconfig['LDAP_GROUP_TO_ROLE_ADMIN'] = ldap_group_admins if ldap_group_admins else 'sg-chn-admins'
    localconfig['LDAP_GROUP_TO_ROLE_USER'] = ldap_group_users if ldap_group_users else 'sg-chn-users'

    with open('config.py.template', 'r') as templfile, open('config.py', 'w') as confile:
        templ = templfile.read()
        for key, setting in localconfig.iteritems():
            templ = templ.replace('{{' + key + '}}', str(setting))
        confile.write(templ)


if __name__ == '__main__':
    generate_config()
