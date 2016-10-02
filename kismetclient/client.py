import socket
import re
import logging

from kismetclient import handlers
from kismetclient.utils import get_csv_args
from kismetclient.utils import get_pos_args

log = logging.getLogger(__name__)


class Command(object):
    # assign at the class level, so these are unique.
    # FIXME race condition.
    command_id = 0

    def __init__(self, command, *opts):
        Command.command_id += 1
        self.command_id = Command.command_id
        self.command = command

        def wrap(opt):
            if ' ' in opt:
                return '\x01%s\x01'
            else:
                return opt
        self.opts = map(wrap, opts)

    def __str__(self):
        return '!%d %s %s' % (self.command_id,
                              self.command,
                              ' '.join(self.opts))


class Response(object):
    protocol = ''
    fields = []

    def __init__(self, res):
        if not res.startswith('*'):
            raise ValueError('Attempted to create a Response object '
                             'from string which did not start with "*"')
        self.protocol, _, tail = res[1:].partition(':')
        fields = re.findall(' \x01(.*?)\x01| ([^ ]+)', tail)
        # only one of the regex fields will match; the other will be empty
        self.fields = [''.join(f) for f in fields]

    def __str__(self):
        return '*%s: %s' % (self.protocol, str(self.fields))


class Client(object):
    def __init__(self, address=('localhost', 2501)):
        self.handlers = {}
        self.protocols = {}
        self.in_progress = {}
        self.register_handler('KISMET',
                              handlers.kismet,
                              send_enable=False)
        self.register_handler('PROTOCOLS',
                              handlers.protocols,
                              send_enable=False)
        self.register_handler('CAPABILITY',
                              handlers.capability,
                              send_enable=False)
        self.register_handler('ACK',
                              handlers.ack,
                              send_enable=False)
        self.register_handler('ERROR',
                              handlers.error,
                              send_enable=False)
        # Open a socket to the kismet server with line-based buffering
        self.file = socket.create_connection(address).makefile('w', 1)

        # Bootstrap the server protocols
        self.listen()  # Kismet startup line
        self.listen()  # Protocols line triggers capabilities requests
        while len(self.in_progress) > 0:
            self.listen()
        # Protocols done populating

    def register_handler(self, protocol, handler, send_enable=True):
        """ Register a protocol handler, and (optionally) send enable
        sentence.
        """
        self.handlers[protocol] = handler
        if send_enable:
            fields = get_csv_args(handler)
            if not fields:
                fields = '*'
            self.cmd('ENABLE', protocol, fields)

    def cmd(self, command, *opts):
        cmd = Command(command, *opts)
        log.debug(cmd)
        self.in_progress[str(cmd.command_id)] = cmd
        self.file.write(str(cmd) + '\n')

    def listen(self):
        line = self.file.readline().rstrip('\n')
        r = Response(line)
        log.debug(r)
        handler = self.handlers.get(r.protocol)
        if handler:
            fields = r.fields
            if get_pos_args(handler):
                # just the named parameters in handler
                return handler(self, *fields)
            else:
                # all parameters in default order
                field_names = self.protocols.get(r.protocol, [])
                # If the protocol fields aren't known at all, we don't
                # handle the message.
                if field_names:
                    named_fields = dict(zip(field_names, fields))
                    return handler(self, **named_fields)
