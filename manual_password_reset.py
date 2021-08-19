from flask_security.utils import hash_password
from chn.auth.models import User
from chn import chn, db
import sys
from getpass import getpass
import argparse


def parse_args():

    parser = argparse.ArgumentParser(description='Reset a password for user')
    parser.add_argument('-u', '--username', help='Username to reset')
    parser.add_argument('-p', '--password', help='New password')

    return parser.parse_args()


def main():

    args = parse_args()

    with chn.test_request_context():

        if not args.username:
            email = input("Enter email address: ").strip()
        else:
            email = args.username

        if not args.password:
            password = getpass("Enter new password: ")
            password2 = getpass("Enter new password (again): ")

            if password != password2:
                sys.stderr.write("Passwords didn't match, try again\n")
                return 1
        else:
            password = args.password

        user = User.query.filter_by(email=email).first()
        if user:
            print("user found, updating password")
            user.password = hash_password(password)
            db.session.add(user)
            db.session.commit()
        else:
            sys.stderr.write("No user with that email address was found.\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
