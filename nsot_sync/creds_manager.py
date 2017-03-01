import getpass
import base64
import os.path
import logging
__author__ = 'liorf'

logger = logging.getLogger(__name__)


class CredsManager:
    """
    This class needs to get the filename of the credentials and a flag update_creds, if not set will be False.
    """
    def __init__(self, **kwargs):
        self.update_creds = False
        self.creds_filename = ''
        if kwargs is not None:
            for key, value in kwargs.iteritems():
                if key == 'name':
                    self.creds_filename = value
                if key == 'update_creds':
                    self.update_creds = value
        else:
            raise Exception('Error: kwargs is None')

        self.creds_filename = os.path.normpath(os.path.expanduser('~') + '/.' + self.creds_filename)
        # print (self.creds_filename)
        # print (os.path.expanduser('~'))
        # exit(0)


    @property
    def load_creds(self):
        """
        This function Checks if update_creds is set, if so the user will get the username and password prompt.
         If not, the tool will try to load the credentials from the file.
        :return the username and password
        """
        if self.update_creds:
            user = raw_input('Enter Username: ')
            if user == "":
                logger.info('No username given')
                raise Exception("No username given")
            password = getpass.getpass()
            if password == "":
                logger.info('No password given')
                raise Exception("No password given")
            with open(self.creds_filename, 'w') as f:
                f.write(user + "\n")
                f.write(base64.b64encode(password))
                f.close()
                return user, password
        else:
            if os.path.isfile(self.creds_filename):
                with open(self.creds_filename, 'r') as f:
                    user = f.readline().strip()
                    password = base64.b64decode(f.readline().strip())
                f.close()
                return user, password
            else:
                logger.info('No user found in cache')
                user = raw_input('Enter Username: ')
                if user == "":
                    logging.info('No username given')
                    raise Exception("Error: No username given")
                password = getpass.getpass()
                if password == "":
                    logger.info('No password given')
                    raise Exception("Error: No password given")
                with open(self.creds_filename, 'w') as f:
                    f.write(user + "\n")
                    f.write(base64.b64encode(password))
                    f.close()
                return user, password
