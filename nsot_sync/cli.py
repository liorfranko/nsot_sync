'''
CLI
---

cli.main is the entrypoint for the program, which should call to cli()


DynamicLoader allows loading ``cli()`` from any script under ``commands`` as a
Click command. This is where the driver entrypoints should be.
'''

from __future__ import print_function
import os
import click

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
PLUGIN_FOLDERS = [
    os.path.join(os.path.dirname(__file__), 'commands'),
]


class DynamicLoader(click.MultiCommand):

    def fetch_dynamic_cmds(self):
        dynamic_cmds = {}
        for folder in PLUGIN_FOLDERS:
            for filename in os.listdir(folder):
                if filename.endswith('.py') and filename != '__init__.py':
                    cmdname = filename[:-3]
                    full_path = os.path.join(folder, filename)
                    dynamic_cmds.update({cmdname: full_path})

        return dynamic_cmds

    def list_commands(self, ctx):
        dynamic_cmds = self.fetch_dynamic_cmds()

        cmds = dynamic_cmds.keys()
        cmds.sort()
        return cmds

    def get_command(self, ctx, name):
        dynamic_cmds = self.fetch_dynamic_cmds()

        ns = {}
        fn = dynamic_cmds[name]
        with open(fn) as f:
            code = compile(f.read(), fn, 'exec')
            eval(code, ns, ns)
        return ns['cli']


@click.command(cls=DynamicLoader, context_settings=CONTEXT_SETTINGS)
@click.version_option(None, '-V', '--version')
@click.option('--noop', is_flag=True, help='no-op mode')
@click.option('--verbose', '-v', count=True, help='Verbose logging')
@click.option(
    '--site-id',
    '-s',
    default=1,
    type=int,
    help='NSoT site id to sync to'
)
@click.pass_context
def cli(ctx, noop=False, site_id=1, verbose=0):
    '''nsot_sync creates/updates resources in an NSoT instance

    By default, nsot_sync will manage network and interface resources along
    with a device resource. This is customizable via the drivers.

    The drivers are the available commands. (eg, facter and simple) Custom
    drivers can be requested or added at https://github.com/coxley/nsot_sync
    '''

    # Configure logging, which only needs to be done in one spot for an entire
    # application. Other modules will create instances of .get_logger()
    import coloredlogs
    if verbose >= 2:
        log_level = 'DEBUG'
    elif verbose == 1:
        log_level = 'INFO'
    elif verbose == 0:
        log_level = 'WARNING'

    coloredlogs.install(level=log_level)

    ctx.obj['SITE_ID'] = site_id
    ctx.obj['NOOP'] = noop
    ctx.obj['VERBOSE'] = verbose


def main():
    cli(obj={})  # obj is for sharing things between click contexts
