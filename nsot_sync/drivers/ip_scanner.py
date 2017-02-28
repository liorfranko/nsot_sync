from base_driver import BaseDriver
from pynsot.client import get_api_client
import ipaddress
import concurrent.futures
import time
import datetime
import logging
from common import find_host_in_network, resolve_host, check_icmp, info, success # FIXME !!!!
from requests.exceptions import ConnectionError
from pynsot.vendor.slumber.exceptions import HttpClientError
import os
import sys

WORKING_DIR = os.path.dirname(os.path.realpath(__file__))
MODULES_DIR = os.path.normpath(WORKING_DIR + '/../../modules/')
sys.path.insert(0, MODULES_DIR)

__author__ = 'Lior Franko'
__maintainer__ = 'Lior Franko'
__email__ = 'liorfranko@gmail.com'


# TODO Work with Jathan on running the driver for all sites.
# TODO Add summary mail?


class IpScannerDriver(BaseDriver):
    """
    IP Scanner

    The driver works on one site, if not specified it will work on site 1.
    The driver will only scan the networks which have 'scan' attribute and is set to true.
    It will uses the OS PING process, parse the response to understand if the IP is reachable or not.
    It will then try to get the DNS resolve for the reachable IP's.
    For already existing IP's, it will only update the following attributes (It will preserve all the other existing attributes):
        dns_resolve - The current DNS resolve.
        last_reachable - The current time stamp of the local OS.
        desc - "Discovered by ip_scanner"
    For new discovered IP's it will add the network with the mentioned attributes (dns_resolve, last_reachable, desc).

    NOTES:
        * The driver is multithreaded, by default it runs 100 threads, to control it use --max-threads.
        * The driver has been tested on macOS and Centos7.2, it might not parse correctly the ICMP response of other OS's.
          If so, please open issue and I'll fix it.
    """
    REQUIRED_ATTRS = [
        {
            'name': 'desc',
            'resource_name': 'Network',
            'description': 'Description',
            'display': True,
            'required': False,
        },
        {
            'name': 'dns_resolve',
            'resource_name': 'Network',
            'description': 'The reverse DNS resolve',
            'display': True,
            'required': False,
        },
        {
            'name': 'last_reachable',
            'resource_name': 'Network',
            'description': 'The time stap of the last successful scan',
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
        }
    ]
    REACHABLE_ICMP_RESPONSES = ['1 received', '1 packets received']

    def __init__(self, max_threads, scan_all, scan_all_update, *args, **kwargs):
        super(IpScannerDriver, self).__init__(*args, **kwargs)
        self.site_id = self.click_ctx.obj['SITE_ID']
        self.logger = logging.getLogger(__name__)
        self.c = get_api_client()
        self.network_to_update = []
        self.exit_app = False
        self.scan_all = scan_all
        self.scan_all_update = scan_all_update
        self.max_threads = max_threads

        try:
            self.logger.info('Getting networks for site: %s', self.site_id)
            # self.networks = self.c.sites(self.site_id).networks.get()
            import json
            # from pprint import pprint

            with open('/Users/liorf/Dropbox/Work/Liveperson/Code/python/nsot_networks.json') as data_file:
                self.networks = json.load(data_file)
            # pprint(self.networks)
            # print(json.dumps(self.networks, sort_keys=True, indent=4))
            # exit()
        except ConnectionError:
            self.click_ctx.fail('Cannot connect to NSoT server')
        except HttpClientError as e:
            self.handle_pynsot_err(e)
        except Exception:
            self.logger.exception('IpScannerDriver, getting existing net')

    def get_resources(self):  # -> Dict[string, list]
        """
        Loop over the networks for the given site_id.
        """
        if self.scan_all_update:
            self.logger.debug('Looping to add the scan attribute.')
            self.add_scan_to_all()
        else:
            try:
                self.logger.debug('Looping to scan networks.')
                for net in self.networks:
                    self.network_loop(net)
            except KeyboardInterrupt:
                self.exit_app = True
                raise
        return {
            'networks': self.network_to_update,
            'interfaces': [],
            'devices': []
        }

    def network_loop(self, net):
        """
        Checking the network is not IP and scan attribute set to true and start scanning all the hosts.
        :param net: The network list for the given site_id
        :return: If the network is ip or scan attribute set to something else rather than true, return.
        """
        self.logger.debug('Network:\n%s', net)
        network_address = net['network_address']
        prefix_length = net['prefix_length']
        full_net = ("%s%s%s" % (network_address, '/', prefix_length))

        if net['is_ip']:
            self.logger.info('%s - Is ip and not subnet, skipping the scan.', full_net)
            return
        self.logger.info('%s - Is network and not ip, continue the scan.', full_net)

        if self.scan_all:
            self.logger.debug('%s - Scan-all flag is used, skipping the other checks and scanning the network.',
                              full_net)
        else:
            self.logger.debug('%s - Scan-all flag is not used, running normal checks.', full_net)
            if 'scan' not in net['attributes']:
                self.logger.debug('%s - Scan attribute not exists for the network, skipping the scan.', full_net)
                return
            self.logger.debug('%s - Scan attribute exists for the network, continue the scan.', full_net)

            if not net['attributes']['scan'].lower() == 'true':
                self.logger.debug('%s - The scan attribute for the network is not set to true.', full_net)
                return
            self.logger.debug('%s - The scan attribute set to true, starting to scan the network.', full_net)

        subnet = ipaddress.ip_network(u'' + full_net, strict=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for ip in subnet.hosts():
                executor.submit(self.scan, str(ip))

    def scan(self, ip):
        """
        Check ICMP reachability to the IP address.
        If reachable, Check if exists in NSoT, if not add the IP if exists update the time stamp and DNS resolve to NSoT
        :param ip: IP address to check.
        :return: Return to skip the ip, or when done.
        """
        while not self.exit_app:
            if not check_icmp(ip, self.logger):
                return

            host = find_host_in_network(ip, self.networks)

            dns_hostname = resolve_host(ip)
            self.logger.debug('%s - DNS resolve is %s', ip, dns_hostname)

            ts = time.time()
            st = datetime.datetime.fromtimestamp(ts).strftime('%b %d %H:%M:%S')
            self.logger.debug('%s - The time stamp is %s', ip, st)

            if not host:
                self.logger.debug('%s - Not exist in IPAM', ip)
                network_resource = {
                    'is_ip': True,
                    'network_address': ip,
                    'site_id': self.site_id,
                    'state': 'allocated',
                    'prefix_length': 32,
                    'attributes': {
                        'desc': 'Discovered by ip_scanner',
                        'dns_resolve': dns_hostname,
                        'last_reachable': str(st)
                    }
                }
                self.logger.debug('This network will be added: \n%s', network_resource)
                self.network_to_update.append(network_resource)
                return
            else:
                self.logger.debug('%s - Exist in IPAM, only updating time stamp, DNS and description', ip)
                host['attributes']['dns_resolve'] = dns_hostname
                host['attributes']['last_reachable'] = str(st)
                host['attributes']['desc'] = 'Discovered by ip_scanner'
                network_resource = {
                    'is_ip': True,
                    'network_address': host['network_address'],
                    'site_id': self.site_id,
                    'state': 'allocated',
                    'prefix_length': host['prefix_length'],
                    'attributes': host['attributes']
                }
                self.logger.debug('This network will be updated: \n%s', network_resource)
                self.network_to_update.append(network_resource)
                return

    def add_scan_to_all(self):
        for net in self.networks:
            self.logger.debug('Network:\n%s', net)
            network_address = net['network_address']
            prefix_length = net['prefix_length']
            full_net = ("%s%s%s" % (network_address, '/', prefix_length))
            if not net['is_ip']:
                self.logger.info('%s - Is network and not ip, continue the scan.', full_net)
                net['attributes']['scan'] = 'true'
                network_resource = {
                    'is_ip': net['is_ip'],
                    'network_address': net['network_address'],
                    'site_id': self.site_id,
                    'state': net['state'],
                    'prefix_length': net['prefix_length'],
                    'attributes': net['attributes']
                }
                self.logger.debug('This network will be updated: \n%s', network_resource)
                self.network_to_update.append(network_resource)
