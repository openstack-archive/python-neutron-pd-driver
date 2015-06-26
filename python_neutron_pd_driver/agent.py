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
import signal
import stat
import sys

from threading import Thread

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.linux import pd_driver  # noqa
from neutron.common import config as common_config

from python_neutron_pd_driver import config  # noqa
from python_neutron_pd_driver import constants
from python_neutron_pd_driver import listener
from python_neutron_pd_driver import subnetpd
from python_neutron_pd_driver import utils

LOG = logging.getLogger(__name__)

SUBNET_INFO_FILEPATH = "%s/subnet_%s"


def notify_l3_agent(pid):
    try:
        os.kill(int(pid), signal.SIGHUP)
    except Exception as e:
        LOG.warn(_("Failed to send SIGNUP to %(pid)s: %(exc)s"),
                 {'pid': pid, 'exc': e})


class DHCPV6Agent(Thread):

    def __init__(self):
        super(DHCPV6Agent, self).__init__()
        self.pd_clients = {}
        try:
            subnet_ids = os.listdir(cfg.CONF.pd_confs)
            for subnet_id in subnet_ids:
                if subnet_id[0:7] != "subnet_":
                    continue
                try:
                    with open("%s/%s" % (cfg.CONF.pd_confs, subnet_id)) as f:
                        content = f.readlines()
                    if content:
                        self.enable(subnet_id[7:], content[0])
                except IOError:
                    LOG.warn(_("Failed to read subnet %s info from system!"),
                             subnet_id)
        except OSError:
            LOG.warn(_("Failed to read existing subnet info from system: %s!"),
                     cfg.CONF.pd_confs)

        listener.start()
        utils.socket_delete(constants.CONTROL_PATH)
        self.server = utils.socket_bind(constants.CONTROL_PATH)
        os.chmod(cfg.CONF.pd_socket_loc + '/' +
                 constants.CONTROL_PATH, stat.S_IRWXO)
        self.running = True

    def processor(self, task):
        task = task.split(',')
        if task[0] == 'enable':
            self.enable(task[1], task[2])
        elif task[0] == 'disable':
            self.disable(task[1])
        elif task[0] == 'get':
            prefix = self.get_prefix(task[1])
            path = constants.RESP_PATH % task[2]
            re = utils.socket_connect(path)
            re.send(prefix)

    def run(self):
        while self.running:
            task = self.server.recv(1024)
            utils.new_daemon_thread(self.processor, (task,))

    def stop(self):
        self.running = False
        self.server.shutdown(utils.socket.SHUT_RDWR)
        self.server.close()

    def _write_subnet_info_to_system(self, subnet_id, pid):
        try:
            subnet_list = open(
                SUBNET_INFO_FILEPATH % (cfg.CONF.pd_confs, subnet_id), "w")
            subnet_list.write(pid)
            subnet_list.close()
        except IOError:
            LOG.warn(_("Failed to write subnet info to system!"))

    def _delete_subnet_info_from_system(self, subnet_id):
        if os.path.exists(
            SUBNET_INFO_FILEPATH % (cfg.CONF.pd_confs, subnet_id)):
                os.remove(
                    SUBNET_INFO_FILEPATH % (cfg.CONF.pd_confs, subnet_id))

    def _get_subnet_pd_object(self, subnet_id):
        subnet = self.pd_clients.get(subnet_id)
        if not subnet:
            LOG.warn(_("Prefix delegation not running for %(subnet_id)s"),
                     {'subnet_id': subnet_id})
        return subnet

    def enable(self, subnet_id, pid):
        """Enable/Start a PD client for a subnet"""
        def respond():
            notify_l3_agent(pid)
        if subnet_id not in self.pd_clients:
            conf = {'subnet_id': str(subnet_id), 'pd_update_cb': respond}
            self.pd_clients[subnet_id] = subnetpd.SubnetPD(conf)
            self._write_subnet_info_to_system(subnet_id, pid)
        else:
            respond()
            LOG.debug(_("Prefix delegation already running for %(subnet_id)s"),
                      {'subnet_id': subnet_id})

    def disable(self, subnet_id):
        """Get process back from existing process and kill the process"""
        subnet = self._get_subnet_pd_object(subnet_id)
        if subnet:
            subnet.shutdown()
            del self.pd_clients[subnet_id]
            self._delete_subnet_info_from_system(subnet_id)

    def get_prefix(self, subnet_id):
        """Get Prefix from PD client"""
        subnet = self._get_subnet_pd_object(subnet_id)
        if subnet:
            return subnet.get()
        return "NOT_RUNNING"


def main():
    common_config.init(sys.argv[1:])
    pd_agent = DHCPV6Agent()
    pd_agent.start()

    def signal_handler(signal, frame):
        pd_agent.stop()
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()
