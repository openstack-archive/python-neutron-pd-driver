# Copyright 2015 Cisco Systems
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import Queue
from threading import Timer
import time

from oslo_log import log as logging

from python_neutron_pd_driver import dhcpv6
from python_neutron_pd_driver import listener
from python_neutron_pd_driver import socketv6
from python_neutron_pd_driver import utils

LOG = logging.getLogger(__name__)


class Server(object):

    def __init__(self, serverid, address):
        self.serverid = serverid
        self.address = address[0]


class Prefix(object):

    def __init__(self, ia_prefix):
        self.pref_liftime = dhcpv6.bytes_to_int(ia_prefix[0:4])
        self.valid_liftime = dhcpv6.bytes_to_int(ia_prefix[4:8])
        self.pref_length = dhcpv6.bytes_to_int(ia_prefix[8:9])
        self.prefix = ia_prefix[9: 9 + self.pref_length]

    def __str__(self):
        return ("%s/%s" %
            (dhcpv6.prefix_to_string(self.prefix), self.pref_length))


def create_validator(ty, trid):
    def validator(data):
        if (data[0:1] == ty and
            dhcpv6.bytes_to_int(data[1:4]) == trid):
            return True
        return False
    return validator


class SubnetPD(object):
    def __init__(self, conf):
        super(SubnetPD, self).__init__()
        self.subnet_id = conf['subnet_id']
        self.ready = conf['pd_update_cb']
        self.prefix = "::/64"
        self.server = None
        self.ias = None
        self.renew_timer = None
        self.setup()

    def get(self):
        return str(self.prefix)

    def reset_renew_timer(self):
        self.renew_timer = Timer(self.prefix.pref_liftime, self.renew_prefix)
        self.renew_timer.start()

    def process_REPLY(self, responses):
        # Process reply
        data, sender = responses[0]
        options = dhcpv6.options_to_dict(data)
        ia_pd = options[25][0]
        # T1 = bytes_to_int(ia_pd[4:8])
        # T2 = bytes_to_int(ia_pd[8:12])
        ia_options = dhcpv6.options_to_dict(ia_pd, 12)
        self.prefix = Prefix(ia_options[26][0])

    def renew_prefix(self, pd_choice):
        rn_trid = dhcpv6.gen_trid()

        lis = listener.Listener(create_validator("\x07", rn_trid))
        socketv6.send_packet(dhcpv6.Renew(
            rn_trid, self.subnet_id, self.server.serverid, pd_choice),
            self.server.address)
        res = lis.get()

        if not res:
            raise Exception('RENEW: Failed to get valid REPLY...')

        self.process_REPLY(res)
        self.reset_renew_timer()

    def _solicit(self):
        sol_trid = dhcpv6.gen_trid()

        res = None
        retrys = 3
        validator = create_validator("\x02", sol_trid)
        while not res and retrys > 0:
            lis = listener.Listener(validator, 5)
            time.sleep(1)
            socketv6.send_packet(dhcpv6.Solicit(sol_trid, self.subnet_id))
            res = lis.get()
            retrys = retrys - 1

        if not res:
            raise Exception('Failed to get valid Advertise after 3 retries...')

        highest = -1
        serverid = None
        ia_pd = None
        s_address = None
        for data, sender in res:
            options = dhcpv6.options_to_dict(data)
            preference = dhcpv6.bytes_to_int(options.get(7, [b'\x00'])[0])
            if preference <= highest:
                continue
            highest = preference
            serverid = options[2][0]
            ia_pd = options[25][0]
            s_address = sender

        ia_options = dhcpv6.options_to_dict(ia_pd, 12)
        self.ias = ia_options[26]

        self.server = Server(serverid, s_address)

    def _request(self):
        req_trid = dhcpv6.gen_trid()

        res = None
        retrys = 3
        validator = create_validator("\x07", req_trid)
        while not res and retrys > 0:
            lis = listener.Listener(validator)
            time.sleep(1)
            socketv6.send_packet(dhcpv6.Request(
                req_trid, self.subnet_id, self.server.serverid, self.ias[0]),
                self.server.address)
            res = lis.get()
            retrys = retrys - 1

        if not res:
            raise Exception('Failed to get valid REPLY!')

        self.process_REPLY(res)

    def _release(self):
        rel_trid = dhcpv6.gen_trid()

        validator = create_validator("\x07", rel_trid)
        lis = listener.Listener(validator)
        socketv6.send_packet(dhcpv6.Release(
            rel_trid, self.subnet_id, self.server.serverid, self.ias[0]),
            self.server.address)
        while True:
            try:
                res = lis.get(timeout=10)
                break
            except Queue.Empty:
                socketv6.send_packet(dhcpv6.release(rel_trid,
                    self.server.serverid, self.subnet_id, self.ias[0]),
                    self.server.address)
        return res

    def setup(self):
        def processor():
            LOG.debug(
                "Starting new prefix delegation for %s...", self.subnet_id)

            self._solicit()
            self._request()
            self.reset_renew_timer()

            self.ready()
            LOG.debug("Prefix delegation ready for %s...", self.subnet_id)
        utils.new_daemon_thread(processor, None)

    def shutdown(self):
        try:
            self.renew_timer.cancel()
            self._release()
        except Exception:
            pass
        LOG.debug("Ending prefix delegation for %s, bye!! First try!",
                  self.subnet_id)
        return True
