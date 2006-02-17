"""Exploring how to use YADIS with a revised consumer API.
"""

raise NotImplementedError("For illustration purposes only; "
                          "not a functional fixture.")

import xrd
from yadis.servicetypes.base import IParser
from openid.consumer import consumer
from openid.consumer.factory import OpenIDConsumer
from openid.store import sqlstore

def yadis_services(yadis_url, oid_consumer, *service_types):
    yadis_engine = xrd.ServiceParser([IParser(oid_consumer)])

    xrd_doc = discover(yadis_url)

    service_list = yadis_engine.parse(xrd_doc)

    return service_list.getServices(*service_types)

def begin(yadis_url, oid_consumer, session):
    services = yadis_services(yadis_url, oid_consumer)
    session['yadis_services'] = services
    session['service_index'] = 0

def nextYadisService(session):
    index = session['service_index']
    services = session['yadis_services']
    if len(services) >= index:
        service = services[index]
    else:
        service = None
    session['service_index'] = index + 1
    return service

def authRequest(yadis_url, oid_consumer, session):
    begin(yadis_url, oid_consumer, session)
    return nextYadisService(session)

def authResponse(response_args, session):
    service = session['service']
    status, info = service.complete(response_args)
    if status is not consumer.SUCCESS:
        raise OpenIDError(status, info)

    return info



def main(yadis_url, oid_consumer):
    session = {}

    service = authRequest(yadis_url, oid_consumer, session)

    return_to, return_deferred = makeReturnTo(service)
    webface.redirect(service.constructRedirect(return_to))

    # assuming that return_deferred returns the args it receives.
    return_deferred.addCallback(authResponse, session)

    def badness(failmsg):
        log.msg(failmsg)
        service = nextYadisService(session)
        if service is None:
            return failmsg
        return_to, return_deferred = makeReturnTo(service)
        webface.redirect(service.constructRedirect(return_to))
        return_deferred.addErrback(badness)
        return return_deferred

    return_deferred.addErrback(badness)

    return return_deferred
