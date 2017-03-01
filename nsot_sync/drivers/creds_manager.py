import logging
import getpass
import base64
import os.path
__author__ = 'liorf'


class CredsManager:
    """
    This class needs to get the filename of the credentials and a flag store_creds, if not set will be False.
    """
    def __init__(self, **kwargs):
        self.store_creds = False
        self.creds_filename = ''
        # self.logger = logging.getLogger(__name__)
        # self.creds_folder = ''

        if kwargs is not None:
            for key, value in kwargs.iteritems():
                if key == 'name':
                    self.creds_filename = value
                if key == 'store_creds':
                    self.store_creds = value
        else:
            print ('Error: kwargs is None')
            exit(1)

        self.creds_filename = os.path.normpath(os.path.expanduser('~') + '/' + self.creds_filename + '.dat')

    @property
    def load_creds(self):
        """
        This function Checks if store_creds is set, if so the user will get the username and password prompt.
         If not, the tool will try to load the credentials from the file.
        :return the username and password
        """
        # if not os.path.exists(self.creds_folder):
        #     logging.debug('creds folder does not exists, ' + str(self.creds_folder))
        #     os.makedirs(self.creds_folder)

        if self.store_creds:
            user = raw_input('Enter Username: ')
            if user == "":
                logging.info('No username given')
                print("Error: No username given")
                exit(1)
            password = getpass.getpass()
            if password == "":
                logging.info('No password given')
                print("Error: No password given")
                exit(1)
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
                logging.info('No user found in cache')
                user = raw_input('Enter Username: ')
                if user == "":
                    logging.info('No username given')
                    print("Error: No username given")
                    exit(1)
                password = getpass.getpass()
                if password == "":
                    logging.info('No password given')
                    print("Error: No password given")
                    exit(1)
                with open(self.creds_filename, 'w') as f:
                    f.write(user + "\n")
                    f.write(base64.b64encode(password))
                    f.close()
                return user, password
