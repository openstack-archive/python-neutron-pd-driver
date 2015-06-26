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
import uuid

from oslo_log import log as logging

from neutron.agent.linux import pd_driver

from python_neutron_pd_driver import constants
from python_neutron_pd_driver import exceptions
from python_neutron_pd_driver import utils

LOG = logging.getLogger(__name__)


class PDDriver(pd_driver.PDDriverBase):

    def __init__(self, router_id, subnet_id, ri_ifname):
        super(PDDriver, self).__init__(router_id, subnet_id, ri_ifname)
        self.l3_pid = os.getpid()

    def _send_command(self, command, misc):
        control_socket = utils.control_socket_connect()
        control_socket.send('%s,%s,%s,' % (command, self.subnet_id, misc))

    def enable(self, *args, **kwargs):
        self._send_command('enable', self.l3_pid)

    def disable(self, *args, **kwargs):
        self._send_command('disable', self.l3_pid)

    def get_prefix(self):
        response_id = uuid.uuid4()
        path = constants.RESP_PATH % response_id
        sw = utils.socket_bind(path)
        sw.settimeout(3)
        self._send_command('get', response_id)
        result = sw.recv(1024)
        utils.socket_delete(path)
        if result == "NOT_RUNNING":
            raise exceptions.DHCPv6AgentException(
                msg=("Prefix Delegation not running for %s" % self.subnet_id))
        return result

    @staticmethod
    def get_sync_data():
        return []
