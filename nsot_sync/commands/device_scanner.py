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
@click.pass_context
def cli(ctx, max_threads, scan_vlan):
    driver = device_scanner.DeviceScannerDriver(
        click_ctx=ctx,
        max_threads=max_threads,
        scan_vlan=scan_vlan
    )
    if ctx.obj['NOOP']:
        driver.noop()
        return

    driver.handle_resources()
