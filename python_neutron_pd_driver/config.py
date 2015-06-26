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

from oslo_config import cfg

OPTS = [
    cfg.StrOpt('pd_socket_loc',
               default='/tmp',
               help=_("Location for storing unix sockets for comunication"
                      "between L3 Agent and DHCPv6 Client")),
    cfg.StrOpt('pd_interface',
               default='',
               help=_('Interface to bind to send/receive packets for DHCPv6')),
]

cfg.CONF.register_opts(OPTS)
