"""Teams extension request and response parsing and object representation

This module contains objects representing team extension requests 
and responses that can be used with both OpenID relying parties and
OpenID providers.

    1. The relying party creates a request object and adds it to the
       C{L{AuthRequest<openid.consumer.consumer.AuthRequest>}} object
       before making the C{checkid_} request to the OpenID provider::

        auth_request.addExtension(TeamsRequest(requested=['team']))

    2. The OpenID provider extracts the teams extension request from
       the OpenID request using C{L{TeamsRequest.fromOpenIDRequest}},
       gets the user's approval and team membership, creates a C{L{TeamsResponse}}
       object and adds it to the C{id_res} response::

        teams_req = TeamsRequest.fromOpenIDRequest(checkid_request)
        # [ get the user's approval and team membership, informing the user that
        #   the groups in teams_response were requested and accepted ]
        teams_resp = TeamsResponse.extractResponse(teams_req, group_memberships)
        teams_resp.toMessage(openid_response.fields)

    3. The relying party uses C{L{TeamsResponse.fromSuccessResponse}} to
       exxtract the data from the OpenID response::

        teams_resp = TeamsResponse.fromSuccessResponse(success_response)

@var teams_uri: The URI used for the teams extension namespace and XRD Type Value
"""

from openid.message import registerNamespaceAlias, \
     NamespaceAliasRegistrationError
from openid.extension import Extension
import logging

try:
    basestring #pylint:disable-msg=W0104
except NameError:
    # For Python 2.2
    basestring = (str, unicode) #pylint:disable-msg=W0622

__all__ = [
    'TeamsRequest',
    'TeamsResponse',
    'teams_uri',
    'supportsTeams',
    ]

# The namespace for this extension
teams_uri = 'http://ns.launchpad.net/2007/openid-teams'

try:
    registerNamespaceAlias(teams_uri, 'lp')
except NamespaceAliasRegistrationError, e:
    logging.exception('registerNamespaceAlias(%r, %r) failed: %s' % (teams_uri,
                                                               'teams', str(e),))

def supportsTeams(endpoint):
    """Does the given endpoint advertise support for team extension?

    @param endpoint: The endpoint object as returned by OpenID discovery
    @type endpoint: openid.consumer.discover.OpenIDEndpoint

    @returns: Whether an teams extension type was advertised by the endpoint
    @rtype: bool
    """
    return endpoint.usesExtension(teams_uri)

class TeamsRequest(Extension):
    """An object to hold the state of a teams extension request.

    @ivar requested: A list of team names in this teams extension request
    @type required: [str]

    @group Consumer: requestField, requestFields, getExtensionArgs, addToOpenIDRequest
    @group Server: fromOpenIDRequest, parseExtensionArgs
    """
    ns_uri = 'http://ns.launchpad.net/2007/openid-teams'
    ns_alias = 'lp'

    def __init__(self, requested=None,
                 sreg_ns_uri=self.ns_uri):
        """Initialize an empty teams extension request"""
        Extension.__init__(self)
        self.requested = []

        if requested:
            self.requestTeams(requested)

    def requestedTeams(self):
        return self.requested

    def fromOpenIDRequest(cls, request):
        """Create a simple teams extension request that contains the
        team names that were requested in the OpenID request with the
        given arguments

        @param request: The OpenID request
        @type request: openid.server.CheckIDRequest

        @returns: The newly created teams extension request
        @rtype: C{L{TeamsRequest}}
        """
        self = cls()

        # Since we're going to mess with namespace URI mapping, don't
        # mutate the object that was passed in.
        message = request.message.copy()

        args = message.getArgs(self.ns_uri)
        self.parseExtensionArgs(args)

        return self

    fromOpenIDRequest = classmethod(fromOpenIDRequest)

    def parseExtensionArgs(self, args):
        """Parse the unqualified teams extension request
        parameters and add them to this object.

        This method is essentially the inverse of
        C{L{getExtensionArgs}}. This method restores the serialized teams
        extension team names.

        If you are extracting arguments from a standard OpenID
        checkid_* request, you probably want to use C{L{fromOpenIDRequest}},
        which will extract the teams extension namespace and arguments from the
        OpenID request. This method is intended for cases where the
        OpenID server needs more control over how the arguments are
        parsed than that method provides.

        >>> args = message.getArgs(teams_uri)
        >>> request.parseExtensionArgs(args)

        @param args: The unqualified teams extension arguments
        @type args: {str:str}

        @returns: None; updates this object
        """
        items = args.get('query_membership')
        if items:
            for team_name in items.split(','):
                self.requestTeam(team_name)

    def wereTeamsRequested(self):
        """Have any teams been requested?

        @rtype: bool
        """
        return bool(self.requested)

    def __requests__(self, team_name):
        """Was this team in the request team names?"""
        return team_name in self.requested

    def requestTeam(self, team_name):
        """Request the specified team membership from the OpenID user

        @param team_name: the unqualified team name
        @type team_name: str
        """
        if not team_name in self.requested:
            self.requested.append(team_name)

    def requestTeams(self, team_names):
        """Add the given list of team names to the request.

        @param team_names: The team names to request
        @type team_names: [str]
        """
        if isinstance(team_names, basestring):
            raise TypeError('Teams should be passed as a list of '
                            'strings (not %r)' % (type(field_names),))

        for team_name in team_names:
            self.requestTeam(team_name)

    def getExtensionArgs(self):
        """Get a dictionary of unqualified team extension
        arguments representing this request.

        This method is essentially the inverse of
        C{L{parseExtensionArgs}}. This method serializes the team
        extension request fields.

        @rtype: {str:str}
        """
        args = {}

        if self.requested:
            args['query_membership'] = ','.join(self.requested)

        return args

class TeamsResponse(Extension):
    """Represents the data returned in a simple registration response
    inside of an OpenID C{id_res} response. This object will be
    created by the OpenID server, added to the C{id_res} response
    object, and then extracted from the C{id_res} message by the
    Consumer.

    @ivar data: The simple registration data, keyed by the unqualified
        simple registration name of the field (i.e. nickname is keyed
        by C{'nickname'})

    @ivar ns_uri: The URI under which the simple registration data was
        stored in the response message.

    @group Server: extractResponse
    @group Consumer: fromSuccessResponse
    @group Read-only dictionary interface: keys, iterkeys, items, iteritems,
        __iter__, get, __getitem__, keys, has_key
    """

    ns_uri = 'http://ns.launchpad.net/2007/openid-teams'
    ns_alias = 'lp'

    def __init__(self, teams=None):
        Extension.__init__(self)
        if teams is None:
            self.teams = []
        else:
            self.teams = teams

    def extractResponse(cls, request, teams):
        """Take a C{L{TeamsRequest}} and a list of groups
        the user is member of and create a C{L{TeamsResponse}}
        object containing the list of team names that are both
        requested and in the membership list of the user.

        @param request: The teams extension request object
        @type request: TeamsRequest

        @param teams: The list of teams the user is a member of
        @type teams: [str]

        @returns: a teams extension response object
        @rtype: TeamsResponse
        """
        self = cls()
        for team in request.requestedTeams():
            if team in teams:
                self.teams.append(team)
        return self

    extractResponse = classmethod(extractResponse)

    def fromSuccessResponse(cls, success_response, signed_only=True):
        """Create a C{L{TeamsResponse}} object from a successful OpenID
        library response
        (C{L{openid.consumer.consumer.SuccessResponse}}) response
        message

        @param success_response: A SuccessResponse from consumer.complete()
        @type success_response: C{L{openid.consumer.consumer.SuccessResponse}}

        @param signed_only: Whether to process only data that was
            signed in the id_res message from the server.
        @type signed_only: bool

        @rtype: TeamsResponse
        @returns: A teams extension response with the teams the OpenID
            provider provided.
        """
        self = cls()
        if signed_only:
            args = success_response.getSignedNS(self.ns_uri)
        else:
            args = success_response.message.getArgs(self.ns_uri)

        if not args:
            return None

        self.teams = args['is_member'].split(',')

        return self

    fromSuccessResponse = classmethod(fromSuccessResponse)

    def getExtensionArgs(self):
        """Get the fields to put in the teams extension namespace
        when adding them to an id_res message.

        @see: openid.extension
        """
        return {'is_member': ','.join(self.teams)}
