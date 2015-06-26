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

import mock
import signal
import socket
import struct

from oslo_config import cfg
from oslo_log import log

from neutron.agent.common import config as agent_config
from python_neutron_pd_driver import agent
from python_neutron_pd_driver import config  # noqa
from python_neutron_pd_driver import constants
from python_neutron_pd_driver import dhcpv6
from python_neutron_pd_driver import driver
from python_neutron_pd_driver import exceptions
from python_neutron_pd_driver import listener
from python_neutron_pd_driver import socketv6
from python_neutron_pd_driver import utils
from neutron.agent.linux import pd_driver
from neutron.common import config as base_config
from neutron.tests import base

OPTION_REQUEST = bytearray.fromhex('0006000400170018')
CLIENT_ID = bytearray.fromhex('0001000A0002000022b8') + b'fake'
SERVER_ID = b'\x00\x02\x00\x08' + b'serverid'
ELAPSED = bytearray.fromhex('000800020000')
IAPD = (bytearray.fromhex('0019000c') +
    b'fake' + bytearray.fromhex('00000e1000001518'))
IAPD_WITH_OPTIONS = (b'\x00\x19\x00\x18' + b'fake' +
    b'\x00\x00\x0e\x10\x00\x00\x15\x18\x00\x1a\x00\x08' + b'pdoption')


class TestDHCPV6(base.BaseTestCase):

    def test_gen_trid(self):
        id1 = dhcpv6.gen_trid()
        id2 = dhcpv6.gen_trid()
        self.assertTrue(id1 <= 0xffffff)
        self.assertTrue(id1 >= 0x00)
        self.assertTrue(id2 <= 0xffffff)
        self.assertTrue(id2 >= 0x00)
        self.assertNotEqual(id1, id2)

    def test_bytes_to_int(self):
        results = dhcpv6.bytes_to_int(b'\x19')
        self.assertEqual(results, 25)

    def test_options_to_dict(self):
        data = bytearray.fromhex("021008740019002927fe8f950000000000000000001"
            "a00190000119400001c2040200100000000fe0000000000000000000001000e0"
            "00100011c39cf88080027fe8f950002000e000100011c3825e8080027d410bb")
        results = dhcpv6.options_to_dict(data)
        self.assertTrue(1 in results)
        self.assertTrue(25 in results)
        self.assertTrue(2 in results)

    def test_prefix_to_string(self):
        data = (b'\x22\x22\x00\x00\x22\x22\x45\x76'
                '\x00\x00\x00\x00\x00\x00\x00\x00')
        result = '2222:0:2222:4576::'
        self.assertEqual(dhcpv6.prefix_to_string(data), result)

    def test_DHCPOption(self):
        data = b'fake'
        option = dhcpv6.DHCPOption()
        option.data = data
        expected = b'\x00\x00\x00\x04'
        expected += data
        self.assertEqual(expected, option.to_bytes())

    def test_ClientIdentifier_bytes(self):
        clientid = dhcpv6.ClientIdentifier()
        clientid.xargs['EnterpriseNum'] = 8888
        clientid.xargs['EnterpriseID'] = b'fake'
        self.assertEqual(CLIENT_ID, clientid.to_bytes())

    def test_ServerIdentifier_bytes(self):
        serverid = dhcpv6.ServerIdentifier(b'serverid')
        self.assertEqual(SERVER_ID, serverid.to_bytes())

    def test_OptionRequest_bytes(self):
        optReq = dhcpv6.OptionRequest()
        self.assertEqual(OPTION_REQUEST, optReq.to_bytes())

    def test_ElapsedTime_bytes(self):
        time = dhcpv6.ElapsedTime()
        self.assertEqual(ELAPSED, time.to_bytes())

    def test_IAPD_bytes(self):
        ia_pd = dhcpv6.IAPD('fake-name')
        self.assertEqual(IAPD, ia_pd.to_bytes())

    def test_IAPD_with_options_bytes(self):
        ia_pd = dhcpv6.IAPD('fake-name', 'pdoption')
        self.assertEqual(IAPD_WITH_OPTIONS, ia_pd.to_bytes())

    def _test_message_bytes(self, packet, expected_type, extra_args=[]):
        msg = packet(9999, 'fake', *extra_args).to_bytes()
        self.assertEqual(expected_type, msg[0:1])
        self.assertEqual(dhcpv6.int_to_bytes(9999, 6), msg[1:4])
        self.assertTrue(OPTION_REQUEST in msg)
        self.assertTrue(CLIENT_ID in msg)
        return msg

    def test_DHCPMessage_bytes(self):
        self._test_message_bytes(dhcpv6.DHCPMessage, b'\x00')

    def test_Solicit_bytes(self):
        sol = self._test_message_bytes(dhcpv6.Solicit, b'\x01')
        self.assertTrue(ELAPSED in sol)
        self.assertTrue(IAPD in sol)

    def _test_response_message_bytes(self, packet, expected_type):
        args = ['serverid', 'pdoption']
        msg = self._test_message_bytes(packet, expected_type, args)
        self.assertTrue(SERVER_ID in msg)
        self.assertTrue(IAPD_WITH_OPTIONS in msg)
        return msg

    def test_DHCPResponseMessage_bytes(self):
        self._test_response_message_bytes(dhcpv6.DHCPResponseMessage, b'\x00')

    def test_Request_bytes(self):
        self._test_response_message_bytes(dhcpv6.Request, b'\x03')

    def test_Renew_bytes(self):
        self._test_response_message_bytes(dhcpv6.Renew, b'\x05')

    def test_Release_bytes(self):
        msg = self._test_response_message_bytes(dhcpv6.Release, b'\x08')
        self.assertTrue(ELAPSED in msg)


class TestDHCPv6API(base.BaseTestCase):

    def setUp(self):
        super(TestDHCPv6API, self).setUp()
        mock.patch('os.getpid', return_value='12345').start()
        mock.patch('uuid.uuid4', return_value='uuid').start()
        self.pd_manager = driver.PDDriver("router", "subnet", "blah")
        self.socket = mock.patch('socket.socket').start()

    def _send_command(self):
        self.pd_manager._send_command("command", "misc")
        self.socket().send.assert_called_once_with('command,subnet,misc,')

    def test_enable(self):
        self.pd_manager.enable()
        self.socket().send.assert_called_once_with('enable,subnet,12345,')

    def test_disable(self):
        self.pd_manager.disable()
        self.socket().send.assert_called_once_with('disable,subnet,12345,')

    def test_get_prefix(self):
        self.socket().recv.return_value = "prefix"
        prefix = self.pd_manager.get_prefix()
        self.socket().send.assert_called_once_with('get,subnet,uuid,')
        self.assertEqual(prefix, "prefix")

    def test_get_prefix_error_handling(self):
        self.socket().recv.return_value = "NOT_RUNNING"
        self.assertRaises(
            exceptions.DHCPv6AgentException, self.pd_manager.get_prefix)
        self.socket().send.assert_called_once_with('get,subnet,uuid,')

    def test_sync_data(self):
        response = driver.PDDriver.get_sync_data()
        self.assertEqual(response, [])


class TestAgent(base.BaseTestCase):

    def setUp(self):
        super(TestAgent, self).setUp()
        self.subnetpd = mock.patch(
            'python_neutron_pd_driver.subnetpd.SubnetPD').start()
        self.listener = mock.patch(
            'python_neutron_pd_driver.listener.start').start()
        self.listener.isAlive.return_value = False
        self.socket = mock.patch('socket.socket').start()

        self.conf = agent_config.setup_conf()
        cfg.CONF.set_override('state_path', "/tmp/neutron")
        self.conf.set_override('state_path', "/tmp/neutron")
        self.conf.register_opts(base_config.core_opts)
        log.register_options(self.conf)
        self.conf.register_opts(config.OPTS)
        self.conf.register_opts(pd_driver.OPTS)

    def test_notify_l3_agent(self):
        with mock.patch('os.kill') as kill:
            agent.notify_l3_agent(12345)
            kill.assert_called_once_with(12345, signal.SIGHUP)

    def test_notify_l3_agent_exception(self):
        with mock.patch('os.kill') as kill:
            kill.side_effect = Exception("BOOM!")
            agent.notify_l3_agent(12345)
            kill.assert_called_once_with(12345, signal.SIGHUP)

    @mock.patch('os.remove')
    @mock.patch('os.chmod')
    @mock.patch('os.listdir')
    @mock.patch('__builtin__.open')
    def test_DHCPv6Agent___init__(self, mock_open, mock_listdir,
                                  mock_chmod, mock_remove):
        subnet_ids = ["subnet_1", "subnet_2", "subnet_3", "subnet_4"]
        mock_listdir.return_value = subnet_ids
        dc = agent.DHCPV6Agent()
        pd_clients_keys = dc.pd_clients.keys()
        pd_clients_keys.sort()
        self.assertEqual(['1', '2', '3', '4'], pd_clients_keys)
        self.listener.assert_called_once_with()
        self.socket().bind.assert_called_once_with(
            self.conf.pd_socket_loc + "/" + constants.CONTROL_PATH)

    @mock.patch('os.remove')
    @mock.patch('os.chmod')
    @mock.patch('os.listdir')
    @mock.patch('__builtin__.open')
    def test_DHCPv6Agent_system_load_listdir_exception(
            self, mock_open, mock_listdir, mock_chmod, mock_remove):
        mock_listdir.side_effect = OSError()
        dc = agent.DHCPV6Agent()
        self.assertEqual({}, dc.pd_clients)

    @mock.patch('os.remove')
    @mock.patch('os.chmod')
    @mock.patch('os.listdir')
    @mock.patch('__builtin__.open')
    def test_DHCPv6Agent_system_load_open_exception(
            self, mock_open, mock_listdir, mock_chmod, mock_remove):
        subnet_ids = ["subnet_1", "subnet_2", "subnet_3", "subnet_4"]
        mock_listdir.return_value = subnet_ids

        def side_effect(*args, **kwargs):
            if "subnet_4" in args[0]:
                raise IOError()
            return mock.MagicMock()
        mock_open.side_effect = side_effect
        dc = agent.DHCPV6Agent()
        pd_clients_keys = dc.pd_clients.keys()
        pd_clients_keys.sort()
        self.assertEqual(['1', '2', '3'], pd_clients_keys)

    @mock.patch('os.remove')
    @mock.patch('os.chmod')
    @mock.patch('os.listdir')
    @mock.patch('__builtin__.open')
    def test_DHCPv6Agent_processor_enable(
            self, mock_open, mock_listdir, mock_chmod, mock_remove):
        dc = agent.DHCPV6Agent()
        dc.processor('enable,1,12345')
        pd_clients_keys = dc.pd_clients.keys()
        pd_clients_keys.sort()
        self.assertEqual(['1'], pd_clients_keys)
        mock_open.assert_called_once_with(
            "%s/subnet_%s" % (self.conf.pd_confs, 1), 'w')
        mock_open().write.assert_called_once_with('12345')
        mock_open().close.assert_called_once_with()

    @mock.patch('os.remove')
    @mock.patch('os.chmod')
    @mock.patch('os.listdir')
    @mock.patch('__builtin__.open')
    @mock.patch('os.path.exists')
    def test_DHCPv6Agent_processor_disable(
            self, mock_exists, mock_open, mock_listdir, mock_chmod,
            mock_remove):
        dc = agent.DHCPV6Agent()
        subnetpd = mock.Mock()
        dc.pd_clients = {'1': subnetpd}
        dc.processor('disable,1,12345')
        pd_clients_keys = dc.pd_clients.keys()
        pd_clients_keys.sort()
        self.assertEqual([], pd_clients_keys)
        subnetpd.shutdown.assert_called_once_with()
        mock_exists.return_value = True
        mock_remove.assert_called_with(
            "%s/subnet_%s" % (self.conf.pd_confs, 1))

    @mock.patch('os.remove')
    @mock.patch('os.chmod')
    @mock.patch('os.listdir')
    @mock.patch('__builtin__.open')
    def test_DHCPv6Agent_processor_get(
            self, mock_open, mock_listdir, mock_chmod, mock_remove):
        dc = agent.DHCPV6Agent()
        subnetpd = mock.Mock()
        subnetpd.get.return_value = "prefix"
        dc.pd_clients = {'1': subnetpd}
        dc.processor('get,1,12345')
        pd_clients_keys = dc.pd_clients.keys()
        pd_clients_keys.sort()
        subnetpd.get.assert_called_once_with()
        self.socket().connect.assert_called_once_with(
            self.conf.pd_socket_loc + "/" + constants.RESP_PATH % '12345')
        self.socket().send.assert_called_once_with("prefix")


class TestUtils(base.BaseTestCase):

    def setUp(self):
        super(TestUtils, self).setUp()
        self.socket = mock.patch('socket.socket').start()

        self.conf = agent_config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        log.register_options(self.conf)
        self.conf.register_opts(config.OPTS)
        self.conf.register_opts(pd_driver.OPTS)

    def test_socket_connect(self):
        s = utils.socket_connect("hello")
        self.socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect.assert_called_once_with(
            self.conf.pd_socket_loc + "/" + "hello")

    def test_socket_bind(self):
        s = utils.socket_bind("hello")
        self.socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind.assert_called_once_with(
            self.conf.pd_socket_loc + "/" + "hello")

    def test_control_socket_connect(self):
        s = utils.control_socket_connect()
        self.socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect.assert_called_once_with(
            self.conf.pd_socket_loc + "/" + constants.CONTROL_PATH)

    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    def test_socket_delete(self, mock_exists, mock_remove):
        utils.socket_delete("hello")
        mock_exists.return_value = True
        mock_remove.assert_called_once_with(
            self.conf.pd_socket_loc + "/" + "hello")

    @mock.patch('threading.Thread')
    def test_new_daemon_thread(self, mock_thread):
        func = mock.Mock()
        utils.new_daemon_thread(func)
        mock_thread.assert_called_once_with(target=func, args=())

        th = mock_thread()
        self.assertTrue(th.daemon)
        th.start.assert_called_once_with()

    @mock.patch('threading.Thread')
    def test_new_daemon_thread_with_args(self, mock_thread):
        func = mock.Mock()
        arg1 = mock.Mock()
        utils.new_daemon_thread(func, (arg1,))
        mock_thread.assert_called_once_with(target=func, args=(arg1,))

        th = mock_thread()
        self.assertTrue(th.daemon)
        th.start.assert_called_once_with()


class TestSubnetPD(base.BaseTestCase):
    pass


class TestSocketV6(base.BaseTestCase):

    def setUp(self):
        super(TestSocketV6, self).setUp()
        self.socket = mock.patch('socket.socket').start()

        self.conf = agent_config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        log.register_options(self.conf)
        self.conf.register_opts(config.OPTS)
        self.conf.register_opts(pd_driver.OPTS)

    def test_socket_v6(self):
        sock = socketv6.socket_v6()
        self.socket.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt.assert_any_call(socket.SOL_SOCKET,
            socketv6.SO_BINDTODEVICE, self.conf.pd_interface)
        sock.setsockopt.assert_any_call(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt.assert_any_call(
            socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt.assert_any_call(socket.IPPROTO_IPV6,
            socket.IPV6_MULTICAST_HOPS, struct.pack('@i', 1))
        sock.bind.assert_called_once_with(('', 546))

    @mock.patch('python_neutron_pd_driver.socketv6.socket_v6')
    def test_send_packet(self, mock_socketv6):
        socketv6.send_packet("hello")
        mock_socketv6.assert_called_once_with()
        mock_socketv6().settimeout.assert_called_once_with(3)
        mock_socketv6().sendto.assert_called_once_with(
            "hello", ("ff02::1:2", 547))

    @mock.patch('python_neutron_pd_driver.socketv6.socket_v6')
    def test_send_packet_with_non_string(self, mock_socketv6):
        def str(s):
            return "hello"
        pack = mock.Mock()
        pack.__str__ = str
        socketv6.send_packet(pack)
        mock_socketv6.assert_called_once_with()
        mock_socketv6().settimeout.assert_called_once_with(3)
        mock_socketv6().sendto.assert_called_once_with(
            "hello", ("ff02::1:2", 547))

    @mock.patch('python_neutron_pd_driver.socketv6.socket_v6')
    def test_send_packet_with_address(self, mock_socketv6):
        socketv6.send_packet("hello", address="address")
        mock_socketv6.assert_called_once_with()
        mock_socketv6().settimeout.assert_called_once_with(3)
        mock_socketv6().sendto.assert_called_once_with(
            "hello", ("address", 547))


class TestListener(base.BaseTestCase):

    def test_processor(self):

        def validator1(data):
            if data == "good1":
                return True
            return False

        def validator2(data):
            if data == "good2":
                return True
            return False

        def validator3(data):
            if data == "good3":
                return True
            return False

        queue1 = mock.Mock()
        queue2 = mock.Mock()
        queue3 = mock.Mock()
        queue4 = mock.Mock()
        listeners = [(validator1, queue1), (validator1, queue2),
                     (validator2, queue3), (validator3, queue4)]

        listener.processor("good1", "sender1", listeners)
        listener.processor("good2", "sender2", listeners)
        listener.processor("good2", "sender3", listeners)

        queue1.put.assert_called_once_with(("good1", "sender1"))
        queue2.put.assert_called_once_with(("good1", "sender1"))
        queue3.put.assert_any_call(("good2", "sender2"))
        queue3.put.assert_any_call(("good2", "sender3"))
        self.assertFalse(queue4.put.called)

    @mock.patch('python_neutron_pd_driver.socketv6.socket_v6')
    @mock.patch('python_neutron_pd_driver.utils.new_daemon_thread')
    @mock.patch('python_neutron_pd_driver.listener.SOCKET')
    def test_start_not_running(self, mock_SOC, mock_daemon, mock_sock):
        listener.RUNNING = False
        listener.start()
        self.assertEqual(mock_sock(), listener.SOCKET)
        self.assertTrue(listener.RUNNING)
        mock_daemon.assert_called_once_with(listener.main_listener_thread)

    @mock.patch('python_neutron_pd_driver.socketv6.socket_v6')
    @mock.patch('python_neutron_pd_driver.utils.new_daemon_thread')
    @mock.patch('python_neutron_pd_driver.listener.SOCKET')
    def test_start_already_running(self, mock_SOC, mock_daemon, mock_sock):
        listener.RUNNING = True
        mock_sock.return_value = "hello"
        old = listener.SOCKET
        listener.start()
        self.assertEqual(listener.SOCKET, old)
        self.assertFalse(mock_daemon.called)

    def test_stop_running(self):
        listener.SOCKET = mock.Mock()
        listener.RUNNING = True
        listener.stop()
        listener.SOCKET.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        listener.SOCKET.close.assert_called_once_with()
        self.assertFalse(listener.RUNNING)

    def test_stop_not_running(self):
        listener.SOCKET = mock.Mock()
        listener.RUNNING = False
        listener.stop()
        listener.SOCKET.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        listener.SOCKET.close.assert_called_once_with()
        self.assertFalse(listener.RUNNING)

    def test_stop_no_socket(self):
        listener.SOCKET = None
        listener.RUNNING = False
        listener.stop()
        self.assertFalse(listener.RUNNING)
