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

import socket
import struct

from oslo_config import cfg
from oslo_log import log as logging

from python_neutron_pd_driver import config  # noqa

LOG = logging.getLogger(__name__)

SO_BINDTODEVICE = 25


def socket_v6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, cfg.CONF.pd_interface)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS,
                 struct.pack('@i', 1))
    s.bind(('', 546))
    return s


def send_packet(packet, address="ff02::1:2"):
    s = socket_v6()
    s.settimeout(3)
    s.sendto(str(packet), (address, 547))
