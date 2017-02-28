from __future__ import print_function
import click
from nsot_sync.drivers import simple
from nsot_sync.common import validate_csv


@click.command()
@click.option('-i', '--interfaces', callback=validate_csv, default=[],
              help='Limit which interfaces, sep by comma, are synced')
@click.option('-I', '--ignore-intfs', callback=validate_csv, default=[],
              help='Ignore interfaces prefixed with these strings')
@click.pass_context
def cli(ctx, interfaces=[], ignore_intfs=[]):
    '''Simple driver uses system interfaces to generate NSoT resources

    No extra attributes are added to the resources other than linking them
    together
    '''

    driver = simple.SimpleDriver(
        click_ctx=ctx,
        limit_intfs=interfaces,
        ignore_intfs=ignore_intfs,
    )
    if ctx.obj['NOOP']:
        driver.noop()
        return

    driver.handle_resources()
