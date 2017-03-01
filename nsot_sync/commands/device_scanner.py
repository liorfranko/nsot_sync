from __future__ import print_function
import click
from nsot_sync.drivers import device_scanner


@click.command()
@click.option(
    '--max-threads',
    '-m',
    default=100,
    type=int,
    help='Maximum threads for the network scan, default is 100.'
)
@click.option('--scan-vlan', type=int, required=True, help='The vlan ID of the management vlan.')
@click.option('--snmp-community', type=str, required=True, help='The SNMP community for auto discovery.')
@click.option('--update-creds', is_flag=True, default=False, help='Update the exiting cached credentials.')
@click.pass_context
def cli(ctx, max_threads, scan_vlan, snmp_community, snmp_version, update_creds):
    driver = device_scanner.DeviceScannerDriver(
        click_ctx=ctx,
        max_threads=max_threads,
        scan_vlan=scan_vlan,
        snmp_community=snmp_community,
        snmp_version=snmp_version,
        update_creds=update_creds
    )
    if ctx.obj['NOOP']:
        driver.noop()
        return

    driver.handle_resources()
