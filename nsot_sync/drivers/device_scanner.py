import logging
from pynsot.client import get_api_client
from pynsot.vendor.slumber.exceptions import HttpClientError
from requests.exceptions import ConnectionError
import ipaddress
import concurrent.futures
from nsot_sync.common import check_icmp, get_hostname, find_device_in_ipam
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from netmiko.snmp_autodetect import SNMPDetect
import time
import datetime

from base_driver import BaseDriver
from creds_manager import CredsManager

__author__ = 'Lior Franko'
__maintainer__ = 'Lior Franko'
__email__ = 'liorfranko@gmail.com'


# TODO Add creds manager as common module.
# TODO Move common function of the two scanners to common module.


class DeviceScannerDriver(BaseDriver):
    REQUIRED_ATTRS = [
        {
            'name': 'address',
            'resource_name': 'Device',
            'description': 'Address',
            'display': True,
            'required': False,
        },
        {
            'name': 'os',
            'resource_name': 'Device',
            'description': 'Operating System',
            'display': True,
            'required': False,
        },
        {
            'name': 'up_time',
            'resource_name': 'Device',
            'description': 'Up time',
            'display': True,
            'required': False,
        },
        {
            'name': 'device_type',
            'resource_name': 'Device',
            'description': 'Device type for netmiko client',
            'display': True,
            'required': False,
        },
        {
            'name': 'scan',
            'resource_name': 'Network',
            'description': 'Set true to scan this network or false to skip',
            'display': True,
            'required': False,
        },
        {
            'name': 'vlan',
            'resource_name': 'Network',
            'description': 'The vlan id of the network',
            'display': True,
            'required': False,
        },
        {
            'name': 'last_reachable',
            'resource_name': 'Device',
            'description': 'The time stap of the last successful scan',
            'display': True,
            'required': False,
        },
    ]
    MGMT_VLAN = '28'
    SNMP_COMMUNITY = 'c+3th#P$un5h_raP'
    SNMP_VERSION = 'v2c'

    def __init__(self, max_threads, scan_all, *args, **kwargs):
        super(DeviceScannerDriver, self).__init__(*args, **kwargs)
        self.site_id = self.click_ctx.obj['SITE_ID']
        self.logger = logging.getLogger(__name__)
        self.c = get_api_client()
        self.devices_to_update = []
        self.exit_app = False
        self.scan_all = scan_all
        self.max_threads = max_threads
        creds_mng = CredsManager(store_creds=False, name=__name__)
        self.user, self.password = creds_mng.load_creds
        # print (os.path.expanduser('~'))
        try:
            self.logger.info('Getting networks for site: %s', self.site_id)
            self.networks = self.c.sites(self.site_id).networks.get()
            # import json
            # with open('/Users/liorf/Dropbox/Work/Liveperson/Code/python/nsot_networks.json') as data_file:
            #     self.networks = json.load(data_file)
            # pprint(self.networks)
            # print(json.dumps(self.networks, sort_keys=True, indent=4))
            # exit()
            # from pprint import pprint
            # with open('/Users/liorf/Dropbox/Work/Liveperson/Code/python/nsot_networks.json') as data_file:
            #     self.networks = json.load(data_file)
            # pprint(data)
            # exit()
            # self.networks =
            self.logger.info('Getting devices for site: %s', self.site_id)
            self.devices = self.c.sites(self.site_id).devices.get()
        except ConnectionError:
            self.click_ctx.fail('Cannot connect to NSoT server')
            raise
        except HttpClientError as e:
            self.handle_pynsot_err(e)
            raise
        except Exception:
            self.logger.exception('DeviceScannerDriver, Getting networks and devices.')
            raise

    def get_resources(self):  # -> Dict[string, list]
        """
        Loop over the networks for the given site_id.
        """
        try:
            self.logger.debug('Looping to scan networks.')
            for net in self.networks:
                self.network_loop(net)
        except KeyboardInterrupt:
            self.exit_app = True
            raise
        return {
            'networks': [],
            'interfaces': [],
            'devices': self.devices_to_update
        }

    def network_loop(self, net):
        self.logger.debug('Network:\n%s', net)
        network_address = net['network_address']
        prefix_length = net['prefix_length']
        full_net = ("%s%s%s" % (network_address, '/', prefix_length))

        # TODO Check if the general IF works!
        # if net['is_ip'] \
        #         or 'vlan' not in net['attributes'] \
        #         or not net['attributes']['vlan'].lower() == self.MGMT_VLAN \
        #         or 'scan' not in net['attributes'] \
        #         or not net['attributes']['scan'].lower() == 'true':
        #     return

        if net['is_ip']:
            self.logger.info('%s - Is ip and not subnet, skipping the scan.', full_net)
            return
        self.logger.info('%s - Is network and not ip, continue the scan.', full_net)

        if 'vlan' not in net['attributes']:
            logging.debug('%s - Could not found vlan attribute, Skipping the scan', full_net)
            return
        logging.debug('%s - Vlan attribute exists', full_net)

        if not net['attributes']['vlan'].lower() == self.MGMT_VLAN:
            logging.debug('%s - Vlan is not %s, Skipping the scan', full_net, self.MGMT_VLAN)
            return
        logging.debug('%s - Vlan is: ', self.MGMT_VLAN)

        if self.scan_all:
            self.logger.debug('%s - Scan-all flag is set, skipping the other checks and scanning the network.',
                              full_net)
        else:
            self.logger.debug('%s - Scan-all flag is not set, running normal checks.', full_net)
            if 'scan' not in net['attributes']:
                self.logger.debug('%s - Scan attribute not exists for this network, skipping the scan.', full_net)
                return
            self.logger.debug('%s - Scan attribute exists for this network, continue the scan.', full_net)

            if not net['attributes']['scan'].lower() == 'true':
                self.logger.debug('%s - The scan attribute for this network is not set to true.', full_net)
                return
            self.logger.debug('%s - The scan attribute set to true, starting to scan the network.', full_net)

        subnet = ipaddress.ip_network(u'' + full_net, strict=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for ip in subnet.hosts():
                executor.submit(self.scan, str(ip))

    def scan(self, ip):
        while not self.exit_app:
            if not check_icmp(ip, self.logger):
                return
            try:
                my_snmp = SNMPDetect(hostname=str(ip), community=self.SNMP_COMMUNITY, snmp_version=self.SNMP_VERSION)
                device_type = my_snmp.autodetect()
            except KeyboardInterrupt:
                self.exit_app = True
                raise
            except Exception as e:
                self.logger.warning('%s - Error trying to get data using SNMP\n%s', ip, e)
                return

            if not device_type:
                self.logger.info('%s - Could not get the device type using SNMP', ip)
                return
            self.logger.debug('%s - Success getting the device_type, %s', ip, device_type)

            device_details = {
                'device_type': device_type,
                'ip': ip,
                'username': self.user,
                'password': self.password,
                'secret': 'secret',
                'verbose': False,
                'global_delay_factor': 2,
            }
            self.logger.debug('%s - device_details is: %s', ip, device_details)
            try:
                net_connect = ConnectHandler(**device_details)
                hostname = get_hostname(device_details, net_connect.find_prompt() + "\n", self.logger)
                if not hostname:
                    self.logger.warning('%s - Error trying to get the hostname', ip)
                    return
                self.logger.debug('%s - Success getting the hostname, %s', ip, hostname)

                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%b %d %H:%M:%S')
                self.logger.debug('%s - The time stamp is %s', ip, st)

                device = find_device_in_ipam(ip, self.devices, self.logger)
                # TODO - Add more attributes here
                if not device:
                    self.logger.info('%s - Not exist in IPAM', ip)
                    attributes = {'address': ip, 'last_reachable': str(st)}
                    device = {'hostname': str(hostname),
                              'attributes': attributes,
                              'device_type': device_type}
                else:
                    self.logger.info('%s - Exist in IPAM', ip)
                    device['attributes']['device_type'] = device_type
                    device['attributes']['last_reachable'] = str(st)
                    device['hostname'] = hostname
                self.devices_to_update.append(device)
            except NetMikoAuthenticationException as e:
                self.logger.info('%s - Login failed, wrong username or password\n%s', ip, e)
            except NetMikoTimeoutException as e:
                self.logger.info('%s - Login failed, TimeoutException\n%s', ip, e)
            except ValueError as e:
                self.logger.info('%s - Login failed, ValueError\n%s', ip, e)
            except KeyboardInterrupt:
                self.exit_app = True
                raise
            finally:
                return
