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
try:
    import Queue
except Exception:
    import queue as Queue
import threading
import time

from python_neutron_pd_driver import socketv6
from python_neutron_pd_driver import utils

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)

LISTENERS = []
RUNNING = False
SOCKET = None


def processor(data, sender, listeners):
    for validate, queue in listeners:
        if validate(data):
            queue.put((data, sender))


def main_listener_thread():
    while RUNNING:
        data, sender = SOCKET.recvfrom(1024)
        utils.new_daemon_thread(processor, (data, sender, LISTENERS))


class Listener(threading.Thread):

    def __init__(self, validator, timetowait=2):
        super(Listener, self).__init__()
        self.validator = validator
        self.timetowait = timetowait
        self.result = Queue.Queue()
        self.start()

    def get(self, *args, **kwargs):
        return self.result.get(*args, **kwargs)

    def run(self):
        packets = Queue.Queue()

        LISTENERS.append((self.validator, packets))
        time.sleep(self.timetowait)
        LISTENERS.remove((self.validator, packets))

        results = []
        while True:
            if packets.empty():
                break
            results.append(packets.get(False))
        self.result.put(results)


def stop():
    global RUNNING
    RUNNING = False
    if SOCKET:
        SOCKET.shutdown(utils.socket.SHUT_RDWR)
        SOCKET.close()


def start():
    global RUNNING, SOCKET
    if not RUNNING:
        RUNNING = True
        SOCKET = socketv6.socket_v6()
        utils.new_daemon_thread(main_listener_thread)
