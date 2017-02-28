from __future__ import print_function
from base_driver import BaseDriver
import socket
import platform
import netifaces


class SimpleDriver(BaseDriver):
    '''Simple driver

    This driver will collect network information via netifaces on the localhost
    then generate NSoT resources for them and the host. The only attribute
    created and applied is 'desc'.

    Note:
        If you're writing a driver to supplement just attributes, consider
        subclassing this class to get the localhost network data.

    Attributes:
        REQUIRED_ATTRS (list): To ensure 'desc' is created for each resource
        INTF_IGNORE_PREFIXES (list): Ignore interfaces.startswith(i)
        INTF_OK_FAMILIES (list): Only add addresses from these address families

    Options:
        limit_intfs (list): Limit interfaces to these if specified.
        ignore_intfs (list): Ignore interfaces starting with these strings
    '''

    REQUIRED_ATTRS = [
        {
            'name': 'desc',
            'resource_name': 'Device',
            'description': 'Description',
            'display': True,
            'required': False,
        },
        {
            'name': 'desc',
            'resource_name': 'Network',
            'description': 'Description',
            'display': True,
            'required': False,
        },
        {
            'name': 'desc',
            'resource_name': 'Interface',
            'description': 'Description',
            'display': True,
            'required': False,
        }
    ]
    INTF_IGNORE_PREFIXES = [
        'lo',
        'docker',
        'fw0',
    ]
    INTF_OK_FAMILIES = [
        netifaces.AF_INET,
        netifaces.AF_INET6,
        netifaces.AF_LINK,
    ]

    def __init__(self, limit_intfs=[], ignore_intfs=[], *args, **kwargs):
        super(SimpleDriver, self).__init__(*args, **kwargs)
        self.limit_intfs = limit_intfs

        # Just override the existing if these are provided
        if ignore_intfs:
            self.INTF_IGNORE_PREFIXES = ignore_intfs

    def get_resources(self):
        '''Returns resources to create

        Will create interfaces, networks, and device for current host

        Returns:
            dict: strings mapped to lists
        '''
        resources_to_create = {}
        resources_to_create.update(self.get_networks_and_interfaces())
        resources_to_create.update({'devices': [self.get_device()]})
        return resources_to_create

    def get_networks_and_interfaces(self):
        '''Using netifaces, generate network and interfaces to create

        Only cares about AFs matching self.INTF_OK_FAMILIES

        Returns:
            dict: {'interfaces': interfaces, 'networks': networks}
        '''
        self.logger.debug('Grabbing interfaces from netifaces')
        networks = []
        interfaces = []
        ignore = self.INTF_IGNORE_PREFIXES
        for intf in netifaces.interfaces():
            if self.limit_intfs and intf not in self.limit_intfs:
                # Move along if not in limit list, should it be provided
                continue
            if not self.limit_intfs and intf.startswith(tuple(ignore)):
                # If not limiting, ignore the ignore prefixes
                continue
            # This loop is a bit weird, but an interface can have many
            # addresses of many address families.
            #
            # This loops through prospecting interfaces, fetching all the
            # possible network resources you can create from it and the
            # interface resource itself.
            self.logger.debug('Iteration %s of prospecting interfaces', intf)
            for net_resources, intf_resource in self.intf_fetch(intf):
                networks.extend(net_resources)
                interfaces.append(intf_resource)

        return {'interfaces': interfaces, 'networks': networks}

    def get_device(self):
        '''Generates single device resource for self

        Returns:
            dict: {'devices': [device]}
        '''
        self.logger.debug('Creating resource for device')
        return {
            'hostname': socket.gethostname().split('.')[0],
            'attributes': {},
        }

    def intf_fetch(self, ifname):
        '''Gathers qualifying address families for a single interface

        Provides the resources to create both all networks on interface and the
        interface itself.

        Returns:
            tuple: (network_resources_list, single_interface_dict)
        '''
        families = netifaces.ifaddresses(ifname)
        try:
            # Not all interfaces have AF_LINK
            mac_addr = families[netifaces.AF_LINK][0]['addr']
        except KeyError:
            mac_addr = '00:00:00:00:00:00'
        networks = []

        for family, addrs in families.iteritems():
            # Loop through all address families, creating network resources
            # from the ones we care about
            if family not in self.INTF_OK_FAMILIES:
                continue

            if family in (netifaces.AF_INET, netifaces.AF_INET6):
                # If needed to quickly do IPv6 prefix length, below might help
                # 16 * len(filter(None, a.split(':'))) for ffff:: netmask
                for addr in addrs:
                    length = family == netifaces.AF_INET and 32 or 128
                    if family == netifaces.AF_INET6:
                        addr['addr'] = addr['addr'].split('%')[0]
                    network_resource = {
                        'is_ip': True,
                        'network_address': addr['addr'],
                        'site_id': self.site_id,
                        'state': 'assigned',
                        'prefix_length': length,
                        'attributes': {
                            'desc': '%s on %s' % (ifname, platform.node()),
                        }
                    }
                    networks.append(network_resource)

        interface = {
            'addresses': ['%s/%s' % (r['network_address'], r['prefix_length'])
                          for r in networks],
            'description': '%s on %s' % (ifname, platform.node()),
            'mac_address': mac_addr,
            'device': socket.gethostname().split('.')[0],
            'attributes': {},
            'type': 6,
            'name': ifname
        }
        return [(networks, interface)]
