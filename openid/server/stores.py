from openid import cryptutil, oidutil

import time

class ServerAssociationStore(object):
    """
    """

    def get(self, assoc_type):
        """
        """
        raise NotImplementedError

    def lookup(self, assoc_handle, assoc_type):
        """
        """
        raise NotImplementedError

    def remove(self, handle):
        """
        """
        raise NotImplementedError

