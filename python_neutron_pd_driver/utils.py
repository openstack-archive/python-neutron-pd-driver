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

import os
import socket
import threading

from oslo_config import cfg

from python_neutron_pd_driver import config  # noqa
from python_neutron_pd_driver import constants


def socket_connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(cfg.CONF.pd_socket_loc + "/" + path)
    return s


def socket_bind(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(cfg.CONF.pd_socket_loc + "/" + path)
    return s


def control_socket_connect():
    return socket_connect(constants.CONTROL_PATH)


def socket_delete(path):
    if os.path.exists(cfg.CONF.pd_socket_loc + "/" + path):
            os.remove(cfg.CONF.pd_socket_loc + "/" + path)


def new_daemon_thread(target, params=None):
    th = threading.Thread(target=target, args=params or ())
    th.daemon = True
    th.start()
    return th
