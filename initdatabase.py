from mhn import create_clean_db
from mhn import mhn, db
from sqlalchemy import create_engine
from sqlalchemy import inspect
import sys

if __name__ == '__main__':
    with mhn.test_request_context():
        inspector = inspect(db.engine)
        if 'user' in inspector.get_table_names():
            print("Database already initialized")
            sys.exit()
        else:
            print("Initializing new database")
            create_clean_db()

