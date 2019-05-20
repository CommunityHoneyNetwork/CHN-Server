from mhn import create_clean_db, reload_scripts, load_custom_scripts
from mhn import mhn, db
from sqlalchemy import create_engine
from sqlalchemy import inspect
import sys


def init_database():
    with mhn.test_request_context():
        inspector = inspect(db.engine)
        if 'user' in inspector.get_table_names():
            print("Database already initialized")
            reload_scripts()
            load_custom_scripts()
            sys.exit()
        else:
            print("Initializing new database")
            create_clean_db()
            load_custom_scripts()


if __name__ == '__main__':
    init_database()
