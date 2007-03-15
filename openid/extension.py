from openid.message import Message

class Extension(object):
    """An interface for OpenID extensions.

    @ivar ns_uri: The namespace to which to add the arguments for this
        extension
    """
    ns_uri = None

    def getExtensionArgs(self):
        """Get the string arguments that should be added to an OpenID
        message for this extension.
        """
        raise NotImplementedError

    def toMessage(self, message=None):
        """Add the arguments from this extension to the provided
        message, or create a new message containing only those
        arguments.

        @returns: The message with the extension arguments added
        """
        if message is None:
            message = Message()

        message.addArgs(self.ns_uri, self.getExtensionArgs())
        return message
