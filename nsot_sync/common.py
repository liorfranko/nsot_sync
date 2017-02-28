from __future__ import print_function
import click
import subprocess

REACHABLE_ICMP_RESPONSES = ['1 received', '1 packets received']


def error(msg):
    click.secho('ERROR: %s' % msg, fg='red', err=True)


def info(msg):
    click.secho('INFO: %s' % msg, fg='blue', err=True)


def success(msg):
    click.secho('SUCCESS: %s' % msg, fg='green', err=True)


def validate_csv(ctx, param, value):
    '''List must be passed as comma separated values

    Having spaces after the comma is fine:

        eth0,eth1, eth2,eth3
        eth,lo, docker,vpn
    '''
    import re

    if not value:
        return []

    try:
        ifnames = re.split(',|, ', value)
        return ifnames
    except:
        raise click.BadParameter(validate_csv.__doc__)


def resolve_host(ip):
    """
    The function try to get the reverse dns name for the IP.
    :param ip: The ip address.
    :return: The reverse dns name or 'No reverse dns resolve'.
    """
    import socket
    try:
        dns_resolve = socket.gethostbyaddr(ip)
        dns_hostname = dns_resolve[0]
    except Exception:
        dns_hostname = 'No reverse dns resolve'
    return dns_hostname


def find_host_in_network(host, network):
    """
    Find the host in the networks list
    :param host: IP address.
    :param network: The network list for the site.
    :return: The net matching the host or None.
    """
    for net in network:
        if net['is_ip']:
            if net['network_address'] == host:
                return net


def check_icmp(ip, logger):
    """
    Check icmp connectivity to the given IP address.
    :param ip: IP address.
    :param logger: The logger.
    :return: True if success, False if failed.
    """
    logger.debug('%s - Checking ICMP', ip)
    reachable = False
    try:
        retval = subprocess.Popen(["ping", "-c1", "-n", "-W1", ip], stdout=subprocess.PIPE)
        out, err = retval.communicate()
        logger.debug('ICMP reply is: ' + str(out))
        for valid_icmp in REACHABLE_ICMP_RESPONSES:
            if valid_icmp in out:
                reachable = True
        if not reachable:
            info('%s - Is unreachable!' % ip)
            return False
        success('%s - Is reachable!' % ip)
        return True
    except Exception as ex:
        error('Unknown error with ICMP!')
        logger.warning('%s - Unknown error with ICMP test\n%s', ip, ex)
        return False


def get_hostname(device, hostname, logger):
    """
    This function remove from the hostname any trailing or leading characters like <, > or #
    :param logger: The logger.
    :param device: The device details in the Netmiko format.
    :param hostname: The hostname returned from the Netmiko.find_prompt()
    :return: The actual hostname, if unknown return None.
    """
    logger.debug('Getting the hostname of device: %s', device)
    logger.debug('Full prompt is: %s', hostname)
    if 'hp' in device['device_type']:
        hostname = hostname.split('<')[1]
        hostname = hostname.split('>')[0]
        return hostname
    elif 'cisco' in device['device_type']:
        if '>' in hostname:
            return hostname.split('>')[0]
        else:
            return hostname.split('#')[0]
    elif 'f5_ltm' in device['device_type']:
        return hostname.split('@')[1].split('(')[1].split(')')[0]
    else:
        logger.warning('device_type unknown - %s', device['device_type'])
        return None


def find_device_in_ipam(ip, devices, logger):
    """
    Find a device by IP address attribute in the list of devices.
    :param ip: The IP address.
    :param devices: The list of NSoT devices.
    :return: The device.
    """
    logger.debug('%s - Getting the device from the devices of NSoT.', ip)
    for device in devices:
        if 'attributes' in device:
            if 'address' in device['attributes']:
                if device['attributes']['address'] == ip:
                    return device
