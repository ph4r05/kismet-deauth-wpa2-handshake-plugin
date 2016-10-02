import logging

from kismetclient.utils import csv
from kismetclient.exceptions import ServerError

log = logging.getLogger(__name__)


def kismet(client, version, starttime, servername, dumpfiles, uid):
    """ Handle server startup string. """
    log.info('Server: ' +
             ' '.join([version, starttime, servername, dumpfiles, uid]))


def capability(client, CAPABILITY, capabilities):
    """ Register a server's default protocol capabilities. """
    client.protocols[CAPABILITY] = csv(capabilities)


def protocols(client, protocols):
    """ Enumerate protocol capabilities so they can be registered. """
    for protocol in csv(protocols):
        client.cmd('CAPABILITY', protocol)


def ack(client, cmdid, text):
    """ Handle ack messages in response to commands. """
    # Simply remove from the in_progress queue
    client.in_progress.pop(cmdid)


def error(client, cmdid, text):
    """ Handle error messages in response to commands. """
    cmd = client.in_progress.pop(cmdid)
    raise ServerError(cmd, text)


def print_fields(client, **fields):
    """ A generic handler which prints all the fields. """
    for k, v in fields.items():
        print '%s: %s' % (k, v)
    print '-' * 80
