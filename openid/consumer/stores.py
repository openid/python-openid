import time

class ConsumerAssociation(object):
    """This class represents a consumer's view of an association."""

    @classmethod
    def fromExpiresIn(cls, expires_in, *args, **kwargs):
        kwargs['issued'] = int(time.time())
        kwargs['lifetime'] = expires_in
        return cls(*args, **kwargs)

    def __init__(self, server_url, handle, secret, issued, lifetime):
        self.server_url = server_url
        self.handle = handle
        self.secret = secret
        self.issued = issued
        self.lifetime = lifetime

    def getExpiresIn(self):
        return max(0, self.issued + self.lifetime - int(time.time()))

    expiresIn = property(get_expires_in)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return self.__dict__ != other.__dict__


class OpenIDStore(object):
    """This is the interface for the consumer's store."""

    def storeAssociation(self, association):
        """Puts a ConsumerAssociation object into storage. No return."""
        raise NotImplementedError
    

    def getAssociation(self, server_url, handle):
        """Returns a ConsumerAssocation object from storage.  Returns
        None if no such association is found.  (Is allowed to gc
        expired associations when found and return None instead of the
        invalid association.)"""
        raise NotImplementedError

    def removeAssociation(self, server_url, handle):
        """If there is a matching association, remove it from the
        store and return True.  Otherwise return False."""
        raise NotImplementedError


    def storeNonce(self, nonce):
        """Stores a nonce (which is passed in as a string)."""
        raise NotImplementedError

    def useNonce(self, nonce):
        """If the nonce is in the store, removes it and returns True.
        Otherwise returns False.

        This method is allowed and encouraged to treat nonces older
        than some period (like 6 hours) as no longer existing, and
        return False and remove them."""
        raise NotImplementedError

    def getAuthKey(self):
        """This method returns a 20-byte key used to sign the tokens,
        to ensure that they haven't been tampered with in transit.  It
        should return the same key every time it is called."""
        raise NotImplementedError

class FilesystemOpenIDStore(object):
    def __init__(self, directory):
        self.nonce_dir = os.path.join(directory, 'nonces')
        self.association_dir = os.path.join(directory, 'associations')
        self.max_nonce_age = 6 * 60 * 60 # Six hours, in seconds

    def _removeIfPresent(self, filename):
        """Attempt to remove a file, ignoring when a file does not exist"""
        try:
            os.unlink(filename)
        except OSError, why:
            if why[0] == ENOENT:
                pass # Someone beat us to it
            else:
                raise
        
    def getAssociationFilename(self, server_url, handle):
        """Create a unique filename for a given server url and
        handle. This implementation does not assume anything about the
        format of the handle. The filename that is returned will
        contain the domain name from the server URL for ease of human
        inspection of the data directory."""
        parsed_url = urlparse.urlparse(server_url)
        hostport = parsed_url[1]
        host = hostport.split(':', 1)[0]
        sh = sha.new('%s\x00%s' % (server_url, handle)).hexdigest()
        return os.path.join(self.association_dir, host + '.' + sh)

    def storeAssociation(self, association):
        """Store an association in the association directory."""
        filename = self.getAssociationFilename(association.server_url,
                                               association.handle)
        tmp = filename + '.tmp'

        # Make sure no one else is attempting to write to this file at
        # the same time. This should never happen under normal
        # conditions, but this will give us an exception if there is a
        # bug or misuse of the store instead of corrupting data.
        tmp_fd = os.open(tmp, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        try:
            tmp_file = os.fdopen(fd, 'wb')
        except:
            os.close(tmp_fd)
            raise

        # Write the pickled association to disk safely
        try:
            try:
                cPickle.dump(association, tmp_file, -1)
                os.fsync(tmp_fd)
            finally:
                tmp_file.close()
        except:
            # If there was an error, don't leave the temporary file
            # around
            self._removeIfPresent(filename)
            raise

        # It's OK if the file already exists, as long as the data that
        # is there is consistent.
        os.rename(tmp, filename)

    def getAssociation(self, server_url, handle):
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
                try:
                    association = cPickle.load(assoc_file)
                except UnpicklingError:
                    association
            finally:
                assoc_file.close()

        # Clean up expired associations
        if association.getExpiresIn() == 0:
            self._removeIfPresent(filename)
            return None
        else:
            return association

    def removeAssociation(self, server_url, handle):
        filename = self.getAssociationFilename(server_url, handle)
        self._removeIfPresent(filename)

    def storeNonce(self, nonce):
        filename = os.path.join(self.nonce_dir, nonce)
        nonce_file = file(filename, 'w')
        nonce_file.close()

    def useNonce(self, nonce):
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

    def collect(self):
        """Remove expired entries from the database. This is
        potentially expensive, so only run when it is acceptable to
        take time."""
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
                    self._removeIfPresent(filename)

        association_filenames = os.listdir(self.association_dir)
        for association_filename in association_filenames:
            try:
                association_file = file(association_file, 'rb')
            except IOError, why:
                if why[0] == ENOENT:
                    pass
                else:
                    raise
            else:
                try:
                    association = cPickle.load(
