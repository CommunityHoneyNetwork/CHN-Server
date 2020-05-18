import os
from urllib.parse import urlparse

import initdatabase
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

try:
    import config
except ImportError:
    print('It seems like this is the first time running the server.')
    print('First let us generate a proper configuration file.')
    try:
        from generateconfig import generate_config
        generate_config()
        import config
        print('Initializing database "%s".' % config.SQLALCHEMY_DATABASE_URI)
        initdatabase.init_database()
    except Exception as e:
        print(e)
        print('An error ocurred. Please fix the errors and try again.')
        print('Deleting "config.py" file.')
        try:
            os.remove('config.py')
            os.remove('config.pyc')
        finally:
            raise SystemExit('Exiting now.')

from mhn import mhn, db

if __name__ == '__main__':
    migrate = Migrate(mhn, db)
    manager = Manager(mhn)
    manager.add_command('db', MigrateCommand)

    @manager.command
    def run():
        # Takes run parameters from configuration.
        serverurl = urlparse(config.SERVER_BASE_URL)
        mhn.run(debug=config.DEBUG, host='0.0.0.0',
                port=serverurl.port)

    @manager.command
    def runlocal():
        serverurl = urlparse(config.SERVER_BASE_URL)
        mhn.run(debug=config.DEBUG, host='0.0.0.0',
                port=serverurl.port)

    manager.run()
