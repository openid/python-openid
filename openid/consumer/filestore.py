import string
import os
import os.path
import time
import tempfile

from errno import EEXIST, ENOENT

from openid.consumer.stores import OpenIDStore, ConsumerAssociation
from openid import util

filename_allowed = string.letters + string.digits + '.-'
# Convert this to something whose __contains__ is fast
try:
    # 2.4
    alphanum = set(filename_allowed)
except NameError:
    try:
        # 2.3
        import sets
    except ImportError:
        # pre-2.3
        _d = {}
        for c in filename_allowed:
            _d[c] = None
        filename_allowed = _d
    else:
        filename_allowed = sets.Set(filename_allowed)

# The ordering and name of keys as stored by serializeAssociation
assoc_keys = [
    'version',
    'server_url',
    'handle',
    'secret',
    'issued',
    'lifetime',
    ]

def serializeAssociation(assoc):
    """Convert an association to kvform

    Inverse of deserializeAssociation
    """
    data = [
        '1',
        assoc.server_url,
        assoc.handle,
        util.to_b64(assoc.secret),
        str(int(assoc.issued)),
        str(int(assoc.lifetime)),
        ]

    assert len(data) == len(assoc_keys)

    lines = []
    for k, v in zip(assoc_keys, data):
        assert ':' not in k
        if '\n' in v:
            fmt = 'Invalid value serializing association: field %r, value %r'
            raise ValueError(fmt % (k, v))

        lines.append('%s: %s\n' % (k, v))

    return ''.join(lines)

def deserializeAssociation(assoc_s):
    """Parse an association as stored by serializeAssociation.

    inverse of serializeAssociation
    """
    lines = assoc_s.split('\n')
    if lines.pop() != '':
        raise ValueError('Missing trailing newline!')
    keys = []
    values = []
    for line in lines:
        k, v = line.split(': ')
        keys.append(k)
        values.append(v)

    if keys != assoc_keys:
        raise ValueError('Unexpected key values: %r', keys)

    version, server_url, handle, secret, issued, lifetime = values
    if version != '1':
        raise ValueError('Unknown version: %r' % version)
    issued = int(issued)
    lifetime = int(lifetime)
    secret = util.from_b64(secret)
    return ConsumerAssociation(server_url, handle, secret, issued, lifetime)

def removeIfPresent(filename):
    """Attempt to remove a file, returning whether the file existed at
    the time of the call.

    str -> bool
    """
    try:
        os.unlink(filename)
    except OSError, why:
        if why[0] == ENOENT:
            # Someone beat us to it, but it's gone, so that's OK
            return False
        else:
            raise
    else:
        # File was present
        return True

def ensureDir(dir_name):
    """Create dir_name as a directory if it does not exist. If it
    exists, make sure that it is, in fact, a directory.

    Can raise OSError

    str -> NoneType
    """
    try:
        os.makedirs(dir_name)
    except OSError, why:
        if why[0] != EEXIST or not os.path.isdir(dir_name):
            raise

class FilesystemOpenIDStore(object):
    """Filesystem-based store for OpenID associations and nonces.

    Methods of this object can raise OSError if unexpected filesystem
    conditions, such as bad permissions or missing directories, occur.
    """

    AUTH_KEY_LEN = 20

    def __init__(self, directory):
        """Initialize the nonce and association directories"""
        self.nonce_dir = os.path.join(directory, 'nonces')

        self.association_dir = os.path.join(directory, 'associations')

        # Temp dir must be on the same filesystem as the assciations
        # directory and the directory containing the auth key file.
        self.temp_dir = os.path.join(directory, 'temp')

        self.auth_key_name = os.path.join(directory, 'auth_key')

        self.max_nonce_age = 6 * 60 * 60 # Six hours, in seconds

        self._setup()

    def _setup(self):
        """Make sure that the directories in which we store our data
        exist.

        () -> NoneType
        """
        ensureDir(os.path.dirname(self.auth_key_name))
        ensureDir(self.nonce_dir)
        ensureDir(self.association_dir)
        ensureDir(self.temp_dir)

    def _mktemp(self):
        """Create a temporary file on the same filesystem as
        self.auth_key_name and self.association_dir.

        The temporary directory should not be cleaned if there are any
        processes using the store. If there is no active process using
        the store, it is safe to remove all of the files in the
        temporary directory.

        () -> (file, str)
        """
        fd, name = tempfile.mkstemp(dir=self.temp_dir)
        try:
            file_obj = os.fdopen(fd, 'wb')
            return file_obj, name
        except:
            removeIfPresent(name)
            raise

    def readAuthKey(self):
        """Read the auth key from the auth key file. Will return None
        if there is currently no key.

        () -> str or NoneType
        """
        try:
            auth_key_file = file(self.auth_key_name, 'rb')
        except IOError, why:
            if why[0] == ENOENT:
                return None
            else:
                raise

        try:
            return auth_key_file.read()
        finally:
            auth_key_file.close()

    def setAuthKey(self, auth_key):
        """Safely store the given auth key in the location specified
        by self.auth_key_name.

        It is possible that if there is a power loss or other fatal
        condition, this store will be left without an auth key. In
        that case, one will be generated unless this is called again.

        If other processes are setting different auth keys (especially
        if createAuthKey is being used), then it is possible that this
        function will fail with an OSError. To ensure that this
        function succeeds, it is necessary that there is no other
        process attempting to set a different key. Multiple processes
        attempting to set the same key should not cause any problems.

        str -> NoneType
        """
        if len(auth_key) != self.AUTH_KEY_LEN:
            fmt = ('Attempted to set invalid auth key. Expected %d byte '
                   'string. Got: %r')
            raise ValueError(fmt % (self.AUTH_KEY_LEN, auth_key))
            
        current_key = self.readAuthKey()
        if current_key == auth_key:
            # File exists and the contents match what we were trying
            # to set, so we're done.
            return

        # The contents did not match, so unlink the file.
        removeIfPresent(self.auth_key_name)

        file_obj, tmp = self._mktemp()
        try:
            file_obj.write(auth_key)
            # So that we know that the file will be consistent the
            # next time around.
            os.fsync(file_obj.fileno())

            try:
                os.rename(tmp, self.auth_key_name)
            except OSError, why:
                if why[0] == EEXIST:
                    current_key = self.readAuthKey()
                    if current_key != auth_key:
                        raise
                else:
                    raise
        finally:
            removeIfPresent(tmp)
        
    def createAuthKey(self):
        """Generate a new random auth key and safely store it in the
        location specified by self.auth_key_name.

        This function can interfere with setAuthKey. A given store
        should use only one or the other method for setting the auth
        key.

        () -> str"""

        # Do the import here because this should only get called at
        # most once from each process. Once the auth key file is
        # created, this should not get called at all.
        import random
        rand = random.SystemRandom()

        auth_key = util.random_string(self.AUTH_KEY_LEN, rand)

        file_obj, tmp = self._mktemp()
        try:
            file_obj.write(auth_key)
            os.fsync(file_obj.fileno())

            try:
                if hasattr(os, 'link'):
                    os.link(tmp, self.auth_key_name)
                else:
                    os.rename(tmp, self.auth_key_name)
            except OSError, why:
                if why[0] == EEXIST:
                    auth_key = self.readAuthKey()
                    if auth_key is None:
                        # This should only happen if someone deletes
                        # the auth key file out from under us.
                        raise
                else:
                    raise
        finally:
            removeIfPresent(tmp)

        return auth_key

    def getAuthKey(self):
        """Retrieve the auth key from the file specified by
        self.auth_key_name, creating it if it does not exist.

        () -> str
        """
        try:
            auth_key = self.readAuthKey()
        except (IOError, OSError), why:
            if why[0] == ENOENT:
                auth_key = self.createAuthKey()
            else:
                raise

        if len(auth_key) != self.AUTH_KEY_LEN:
            fmt = ('Got an invalid auth key from %s. Expected %d byte '
                   'string. Got: %r')
            msg = fmt % (self.auth_key_name, self.AUTH_KEY_LEN, auth_key)
            raise ValueError(msg)

        return auth_key

    def getAssociationFilename(self, server_url, handle):
        """Create a unique filename for a given server url and
        handle. This implementation does not assume anything about the
        format of the handle. The filename that is returned will
        contain the domain name from the server URL for ease of human
        inspection of the data directory.

        (str, str) -> str
        """
        server_url = server_url.replace('://', '-', 1)
        filename_chunks = []
        for c in server_url:
            if c in alphanum:
                filename_chunks.append(c)
            else:
                filename_chunks.append('_%02X' % ord(c))
        filename = ''.join(filename_chunks)
        return os.path.join(self.association_dir, filename)

    def storeAssociation(self, association):
        """Store an association in the association directory.

        ConsumerAssociation -> NoneType
        """
        association_s = serializeAssociation(association)
        filename = self.getAssociationFilename(association.server_url,
                                               association.handle)
        tmp_file, tmp = self._mktemp()

        try:
            try:
                tmp_file.write(association_s)
                os.fsync(tmp_file.fileno())
            finally:
                tmp_file.close()

            try:
                os.rename(tmp, filename)
            except OSError, why:
                if why[0] != EEXIST:
                    raise

                # We only expect EEXIST to happen only on Windows. It's
                # possible that we will succeed in unlinking the existing
                # file, but not in putting the temporary file in place.
                try:
                    os.unlink(filename)
                except OSError, why:
                    if why[0] == ENOENT:
                        pass
                    else:
                        raise

                # Now the target should not exist. Try renaming again,
                # giving up if it fails.
                os.rename(tmp, filename)
        except:
            # If there was an error, don't leave the temporary file
            # around.
            removeIfPresent(tmp)
            raise

    def getAssociation(self, server_url, handle):
        """Retrieve an association.

        (str, str) -> ConsumerAssociation or NoneType
        """
        filename = self.getAssociationFilename(server_url, handle)
        try:
            assoc_file = file(filename, 'rb')
        except IOError, why:
            if why[0] == ENOENT:
                # No association exists for that URL and handle
                return None
            else:
                raise
        else:
            try:
                assoc_s = assoc_file.read()
            finally:
                assoc_file.close()

            try:
                association = deserializeAssociation(assoc_s)
            except ValueError:
                removeIfPresent(filename)
                return None

        # If our current association for this server url is not for
        # this handle, return None
        if association.handle != handle:
            return None

        # Clean up expired associations
        if association.getExpiresIn() == 0:
            removeIfPresent(filename)
            return None
        else:
            return association

    def removeAssociation(self, server_url, handle):
        """Remove an association if it exists. Do nothing if it does not.

        (str, str) -> bool
        """
        assoc = self.getAssociation(server_url, handle)
        if assoc is None or assoc.handle != handle:
            return False
        else:
            filename = self.getAssociationFilename(server_url, handle)
            return removeIfPresent(filename)

    def storeNonce(self, nonce):
        """Mark this nonce as present.

        str -> NoneType
        """
        filename = os.path.join(self.nonce_dir, nonce)
        nonce_file = file(filename, 'w')
        nonce_file.close()

    def useNonce(self, nonce):
        """Return whether this nonce is present. As a side effect,
        mark it as no longer present.

        str -> bool
        """
        filename = os.path.join(self.nonce_dir, nonce)
        try:
            st = os.stat(filename)
        except OSError, why:
            if why[0] == ENOENT:
                # File was not present, so nonce is no good
                return False
            else:
                raise
        else:
            # Either it is too old or we are using it. Either way, we
            # must remove the file.
            try:
                os.unlink(filename)
            except OSError, why:
                if why[0] == ENOENT:
                    # someone beat us to it, so we cannot use this
                    # nonce anymore.
                    return False
                else:
                    raise

            now = time.time()
            nonce_age = now - st.st_mtime

            # We can us it if the age of the file is less than the
            # expiration time.
            return nonce_age <= self.max_nonce_age

    def clean(self):
        """Remove expired entries from the database. This is
        potentially expensive, so only run when it is acceptable to
        take time.

        () -> NoneType
        """
        nonces = os.listdir(self.nonce_dir)
        now = time.time()

        # Check all nonces for expiry
        for nonce in nonces:
            filename = os.path.join(self.nonce_dir, nonce)
            try:
                st = os.stat(filename)
            except OSError, why:
                if why[0] == ENOENT:
                    # The file did not exist by the time we tried to
                    # stat it.
                    pass
                else:
                    raise
            else:
                # Remove the nonce if it has expired
                nonce_age = now - st.st_mtime
                if nonce_age > self.max_nonce_age:
                    removeIfPresent(filename)

        association_filenames = os.listdir(self.association_dir)
        for association_filename in association_filenames:
            try:
                association_file = file(association_filename, 'rb')
            except IOError, why:
                if why[0] == ENOENT:
                    pass
                else:
                    raise
            else:
                try:
                    assoc_s = association_file.read()
                finally:
                    association_file.close()

                # Remove expired or corrupted associations
                try:
                    association = deserializeAssociation(assoc_s)
                except ValueError:
                    removeIfPresent(association_filename)
                else:
                    if association.getExpiresIn() == 0:
                        removeIfPresent(association_filename)
