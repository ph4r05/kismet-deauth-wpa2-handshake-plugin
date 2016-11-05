Deauth plugin for Kismet
============

This basic Python plugin for Kismet `runclient.py`.

The main purpose of the plugin is to collect WPA handshakes by actively deauthenticating
connected clients automatically.

The plugin communicates with Kismet server over the kismet protocol on TCP 2501.
Its listening to BSSID, SSID, Client events and builds an internal database of interesting targets.

Once a client on interesting SSID is captured, it is enqueued to a priority queue for deauth.
Another deauth thread scans the deauth queue and performs deauth & handshake collection.

Plugin is designed to use a different WiFi interface than kismet uses not to interfere with the scanning.
Plugin starts airodump-ng on a given channel to capture the handshake, performs deauth and keeps collecting for next
10 seconds waiting for client to authenticate again.

The plugin is based on [kismetclient] repo. For more details take a look at the
[blog](https://deadcode.me/blog/2016/11/05/Active-Deauth-Kismet-Wardriving.html).

kismetclient
============

A Python client for the Kismet server protocol.

Start by creating a client:

```python
from kismetclient import Client as KismetClient

address = ('127.0.0.1', 2501)
k = KismetClient(address)
```

Then register any desired builtin protocol handlers:

```python
from kismetclient import handlers
k.register_handler('TRACKINFO', handlers.print_fields)
```

Create and register a custom protocol handler:

```python
def handle_ssid(client, ssid, mac):
    print 'SSID spotted: "%s" with mac %s' % (ssid, mac)
k.register_handler('SSID', handle_ssid)
```

and call the `listen()` method in a loop:

```python
while True:
    k.listen()
```

The `listen()` method will retrieve responses from the kismet server,
parsing them, and calling registered handlers as appropriate.

`kismetclient` is agnostic about how you loop this call; choose a
method that works well with the rest of your application's
architecture. You could run it in a separate blocking thread that
handles events by parsing them and pushing to a queue, or you could
use gevent to avoid blocking during the socket read call.

A handler is a callable whose first argument is the client generating
the message, with all other arguments named after kismet's protocol
capabilities.  A handler may specify just `client` and `**fields`
parameters in order to get all fields for a message in the default
order.  In general, your handlers should be quick to run and not
depend on other blocking code.

Handlers are registered by calling the `register_handler` method on
the client. The first argument is the name of the protocol to handle,
the second is the function to handle it. It is valid to register a
handler for a protocol which is already handled - in this case the new
handler overrides the old one.

Commands can be sent using `client.cmd(cmd, *args)`:

```python
k.cmd('ENABLE', protocol, fields)
```

The first argument is the kismet command name, followed by the
command arguments.

A trivial example application is included in `runclient.py`. Reading
the source is also likely to be helpful.

To discover which protocols and capabilities your kismet server
supports, start the kismet server and use the interactive python
shell:

```python
>>> from kismetclient import Client
>>> k = Client()
>>> k.protocols.keys()
['CRITFAIL', 'ACK', 'PACKET', 'NETTAG', 'BTSCANDEV', 'CAPABILITY',
'SOURCE', 'COMMON', 'CLISRC', 'TRACKINFO', 'PROTOCOLS', 'BSSIDSRC',
'STATUS', 'WEPKEY', 'STRING', 'SPECTRUM', 'ERROR', 'CHANNEL', 'GPS',
'INFO', 'SSID', 'BSSID', 'PLUGIN', 'BATTERY', 'TERMINATE', 'REMOVE',
'ALERT', 'KISMET', 'CLIENT', 'TIME', 'CLITAG']
>>> k.protocols['GPS']
['lat', 'lon', 'alt', 'spd', 'heading', 'fix', 'satinfo', 'hdop',
'vdop', 'connected']
```

To discover Kismet commands, grep the Kismet source for
`RegisterClientCommand`. At the time of this writing, this list
included: `CAPABILITY`, `ENABLE`, `REMOVE`, `SHUTDOWN`,
`ADDTRACKERFILTER`, `ADDNETCLIFILTER`, `ADDNETTAG`, `DELNETTAG`,
`ADDCLITAG`, `DELCLITAG`, `ADDSOURCE`, `DELSOURCE`, `RESTARTSOURCE`,
`HOPSOURCE`, and `CHANSOURCE`. For usage, consult the source or monitor an
interactive session between the official client and server using
wireshark.

This software is developed using Python 2.7 and the master branch of
Kismet. It may also work on Python 2.6 and earlier versions of Kismet,
but ymmv. Please open tickets for bugs using github.

[kismetclient]: https://github.com/PaulMcMillan/kismetclient