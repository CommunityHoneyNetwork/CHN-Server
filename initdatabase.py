from chn import create_clean_db, reload_scripts, create_superuser_entry
from chn import chn, db
from sqlalchemy import create_engine
from sqlalchemy import inspect
import sys


def init_database():
    with chn.test_request_context():
        inspector = inspect(db.engine)
        if 'user' in inspector.get_table_names():
            print("Database already initialized")
            reload_scripts()
            sys.exit()
        else:
            print("Initializing new database")
            create_clean_db()

if __name__ == '__main__':
    init_database()
