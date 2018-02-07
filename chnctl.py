#!/usr/bin/env python

# Stubbed out right now just to reset passwords
#
# Eventually follow the -ctl model (apachectl, rabbitmqctl)
# and add support for add_user, change_password, etc etc

from flask_security.utils import encrypt_password
from mhn.auth.models import User
from mhn import mhn, db
import argparse
import sys

parser = argparse.ArgumentParser(description="CHN Server CLI Tool")
parser.add_argument('-u',
                    dest='email',
                    required=True,
                    help='User Email Address')
parser.add_argument('-p',
                    dest='password',
                    required=True,
                    help='password')
if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
args=parser.parse_args()

with mhn.test_request_context():
    try:
        user = User.query.filter_by(email=args.email).first()
    except:
        print("Unable to find user %r" % user)

    if user:
        user.password = encrypt_password(args.password)
        try:
            db.session.add(user)
            db.session.commit()
        except:
            print('Unable to update user password')
    else:
        print("No user with that email address was found.")
