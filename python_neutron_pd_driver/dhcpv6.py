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

import logging
import netaddr
import random

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


def gen_trid():
    return random.randint(0x00, 0xffffff)


def bytes_to_int(byt):
    return int(str(byt).encode('hex'), 16)


def int_to_bytes(num, padding=2):
    return bytearray.fromhex(
        '{num:0{padding}x}'.format(padding=padding, num=num))


def options_to_dict(data, pos=4):
    options = {}
    next_pos = pos
    done = False
    while not done:
        option_id = bytes_to_int(data[next_pos: next_pos + 2])
        next_pos = next_pos + 2
        length = bytes_to_int(data[next_pos: next_pos + 2])
        next_pos = next_pos + 2
        if option_id not in options:
            options[option_id] = []
        options[option_id].append(data[next_pos: next_pos + length])
        next_pos = next_pos + length
        if next_pos >= len(data):
            done = True
    return options


def prefix_to_string(prefix):
    pos = 0
    string = prefix[pos: pos + 2].encode('hex')
    pos = pos + 2
    while pos < len(prefix):
        part = prefix[pos: pos + 2].encode('hex')
        string += ":%s" % part
        pos = pos + 2
    address = netaddr.IPAddress(string, 6)
    return str(address)


class Packet(object):

    def to_bytes(self):
        return b''

    def __str__(self):
        return str(self.to_bytes())

    def __repr__(self):
        return repr(self.to_bytes())


class DHCPOption(Packet):
    option_type = 0

    def __init__(self, data=None):
        self.data = b''
        if data:
            self._process_data(data)

    def _process_data(self, data):
        self.option_type = data[0:2]
        self.data = data[2:]

    def to_bytes(self):
        packet = int_to_bytes(self.option_type, 4)
        packet += int_to_bytes(len(self.data), 4)
        packet += self.data
        return packet


def gen_client_id(unique_id):
    clientid = ClientIdentifier()
    clientid.xargs['EnterpriseNum'] = 8888
    clientid.xargs['EnterpriseID'] = unique_id
    return clientid.to_bytes()


class ClientIdentifier(DHCPOption):
    option_type = 1

    def __init__(self, data=None):
        super(ClientIdentifier, self).__init__(data)
        self.duid_type = 2
        self.duid = None
        self.xargs = {}

    def _process_data(self, data):
        super(ClientIdentifier, self)._process_data(data)
        self.duid = data[4:]
        self.duid_type = bytes_to_int(data[4:6])
        if self.duid_type == 2:
            self.xargs['EnterpriseNum'] = bytes_to_int(data[6: 10])
            self.xargs['EnterpriseID'] = data[10:]

    def to_bytes(self):
        self.data = int_to_bytes(self.duid_type, 4)  # DUID Type
        if self.duid_type == 2:
            self.data += int_to_bytes(self.xargs['EnterpriseNum'], 8)
            self.data += self.xargs['EnterpriseID']  # Enterprise ID
        return super(ClientIdentifier, self).to_bytes()


class ServerIdentifier(DHCPOption):
    option_type = 2

    def __init__(self, data=None):
        super(ServerIdentifier, self).__init__()
        self.data = data


class OptionRequest(DHCPOption):
    option_type = 6

    def __init__(self, options=[23, 24], data=None):
        super(OptionRequest, self).__init__(data)
        self.options = options

    def to_bytes(self):
        self.data = b''
        for op in self.options:
            self.data += int_to_bytes(op, 4)
        return super(OptionRequest, self).to_bytes()


class ElapsedTime(DHCPOption):
    option_type = 8

    def __init__(self, time=0, data=None):
        super(ElapsedTime, self).__init__(data)
        self.time = 0

    def to_bytes(self):
        if self.time > 0xffff:
            self.time = 0xffff
        self.data = int_to_bytes(self.time, 4)
        return super(ElapsedTime, self).to_bytes()


class IAPDOption(DHCPOption):
    option_type = 26

    def __init__(self, data=None):
        super(IAPDOption, self).__init__()
        self.data = data


class IAPD(DHCPOption):
    option_type = 25

    def __init__(self, unique_id, pd_options=None, data=None):
        super(IAPD, self).__init__(data)
        self.pd_options = pd_options
        self.unique_id = unique_id

    def to_bytes(self):
        self.data = b''
        self.data += ''.join(self.unique_id.split('-'))[0:4]
        self.data += int_to_bytes(3600, 8)
        self.data += int_to_bytes(5400, 8)
        if self.pd_options:
            self.data += IAPDOption(self.pd_options).to_bytes()
        return super(IAPD, self).to_bytes()


class DHCPMessage(Packet):
    message_type = 0

    def __init__(self, trid, unique_id, data=None):
        self.trid = trid
        self.unique_id = unique_id
        if data:
            self._process_data(data)

    def _process_data(self, data):
        pass

    def to_bytes(self):
        packet = int_to_bytes(self.message_type, 2)
        packet += int_to_bytes(self.trid, 6)
        packet += gen_client_id(self.unique_id)
        packet += OptionRequest().to_bytes()
        return packet


class Solicit(DHCPMessage):
    message_type = 1

    def to_bytes(self):
        packet = super(Solicit, self).to_bytes()
        packet += ElapsedTime().to_bytes()
        packet += IAPD(self.unique_id).to_bytes()
        return packet


class DHCPResponseMessage(DHCPMessage):

    def __init__(self, trid, unique_id, serverid, pd_choice, data=None):
        super(DHCPResponseMessage, self).__init__(trid, unique_id, data)
        self.serverid = serverid
        self.pd_choice = pd_choice

    def to_bytes(self):
        packet = super(DHCPResponseMessage, self).to_bytes()
        packet += ServerIdentifier(self.serverid).to_bytes()
        packet += IAPD(self.unique_id, self.pd_choice).to_bytes()
        return packet


class Request(DHCPResponseMessage):
    message_type = 3


class Renew(DHCPResponseMessage):
    message_type = 5


class Release(DHCPResponseMessage):
    message_type = 8

    def to_bytes(self):
        packet = super(Release, self).to_bytes()
        packet += ElapsedTime().to_bytes()
        return packet
