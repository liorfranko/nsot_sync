import datetime
import logging
import time

import concurrent.futures
import ipaddress
from netmiko.snmp_autodetect import SNMPDetect
from pynsot.client import get_api_client
from pynsot.vendor.slumber.exceptions import HttpClientError
from requests.exceptions import ConnectionError

from base_driver import BaseDriver
from nsot_sync.common import check_icmp, find_device_in_ipam
from nsot_sync.snmp_get_hostname import SNMPHostnameDetect


__author__ = 'Lior Franko'
__maintainer__ = 'Lior Franko'
__email__ = 'liorfranko@gmail.com'
# TODO Add support of SNMP v3


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
            'description': 'Operating System.',
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
        {
            'name': 'hostname',
            'resource_name': 'Device',
            'description': 'The hostname',
            'display': True,
            'required': False,
        },
    ]

    def __init__(self, max_threads, scan_vlan, snmp_community, snmp_version, *args, **kwargs):
        super(DeviceScannerDriver, self).__init__(*args, **kwargs)
        self.site_id = self.click_ctx.obj['SITE_ID']
        self.logger = logging.getLogger(__name__)
        self.c = get_api_client()
        self.devices_to_update = []
        self.exit_app = False
        self.scan_vlan = scan_vlan
        self.snmp_community = snmp_community
        self.snmp_version = snmp_version
        self.max_threads = max_threads
        try:
            self.logger.info('Getting networks for site: %s', self.site_id)
            self.networks = self.c.sites(self.site_id).networks.get()
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

        if not net['attributes']['vlan'].lower() == str(self.scan_vlan):
            logging.debug('%s - Vlan is not %s, Skipping the scan', full_net, self.scan_vlan)
            return
        logging.debug('%s - Vlan is: ', self.scan_vlan)

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
                my_snmp = SNMPDetect(hostname=str(ip), community=self.snmp_community, snmp_version=self.snmp_version)
                os = my_snmp.autodetect()
            except KeyboardInterrupt:
                self.exit_app = True
                raise
            except Exception as e:
                self.logger.warning('%s - Error trying to get data using SNMP\n%s', ip, e)
                return

            if not os:
                self.logger.info('%s - Could not get the os using SNMP', ip)
                return
            self.logger.debug('%s - Success getting the os, %s', ip, os)
            try:
                my_snmp = SNMPHostnameDetect(hostname=str(ip), community=self.snmp_community, snmp_version=self.snmp_version)
                hostname = my_snmp.autodetect()
            except KeyboardInterrupt:
                self.exit_app = True
                raise
            except Exception as e:
                self.logger.warning('%s - Error trying to get hostname using SNMP\n%s', ip, e)
                return

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
                attributes = {'address': ip, 'last_reachable': str(st), 'os': os,
                              'hostname': str(hostname)}
                device = {'hostname': str(hostname),
                          'attributes': attributes}
            else:
                self.logger.info('%s - Exist in IPAM', ip)
                device['attributes']['os'] = os
                device['attributes']['last_reachable'] = str(st)
                device['attributes']['hostname'] = str(hostname)
                device['hostname'] = hostname
            self.devices_to_update.append(device)
            return
