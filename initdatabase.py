from mhn import create_clean_db
from mhn.auth.models import User
from mhn import mhn
import sys

if __name__ == '__main__':
    with mhn.test_request_context():
        users = User.query.all()
        if len(users) >= 1:
            print("Database already initialized")
            sys.exit()
        else:
            create_clean_db()
