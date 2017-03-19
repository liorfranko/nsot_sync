from __future__ import print_function
import click
from nsot_sync.drivers import ip_scanner

__author__ = 'Lior Franko'
__maintainer__ = 'Lior Franko'
__email__ = 'liorfranko@gmail.com'


@click.command()
@click.option(
    '--max-threads',
    '-m',
    default=100,
    type=int,
    help='Maximum threads for the network scan, default is 100.'
)
@click.option(
    '--scan-all',
    is_flag=True,
    help='Scan all the networks in the site, will not change the scan attribute if exists.'
)
@click.option(
    '--scan-vlan',
    type=int,
    help='The vlan ID of the management vlan.'
)
@click.option(
    '--scan-all-update',
    is_flag=True,
    help='Will only change/add to all the networks scan attribute with set to true, wil not scan the networks.!!'
)
# @click.option('--send-mail', is_flag=True, help='Will only change/add to all the networks scan attribute with set to true, wil not scan the networks.!!')
@click.pass_context
def cli(ctx, max_threads, scan_all, scan_all_update, scan_vlan):
    """
    IP Scanner will scan all the networks for the given site, and update the NSoT on the change.

    If running with --scan-all, it will ignore the fact that a network doesn't have 'scan' attribute or the 'scan' attribute
    is set to something else rather than true.

    If running with --scan-all-update, it will only update/add the 'scan' attribute to all the networks and set it to true.
    """
    driver = ip_scanner.IpScannerDriver(
        click_ctx=ctx,
        max_threads=max_threads,
        scan_all=scan_all,
        scan_all_update=scan_all_update,
        scan_vlan=scan_vlan
    )
    if ctx.obj['NOOP']:
        driver.noop()
        return

    driver.handle_resources()
