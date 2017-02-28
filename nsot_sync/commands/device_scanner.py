from __future__ import print_function
import click
from ..drivers import device_scanner


@click.command()
@click.option(
    '--max-threads',
    '-m',
    default=100,
    type=int,
    help='Maximum threads for the network scan, default is 100.'
)
@click.option('--scan-all', is_flag=True, help='Scan all the networks in the site, will not change the scan attribute if exists.')
@click.pass_context
def cli(ctx, max_threads, scan_all):
    driver = device_scanner.DeviceScannerDriver(
        click_ctx=ctx,
        max_threads=max_threads,
        scan_all=scan_all
    )
    if ctx.obj['NOOP']:
        driver.noop()
        return

    driver.handle_resources()
