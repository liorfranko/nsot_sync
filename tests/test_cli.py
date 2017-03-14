import click
from click.testing import CliRunner
from nsot_sync.cli import cli


def test_basic_exec():
    runner = CliRunner()
    results = {
        'main_help': runner.invoke(cli, ['--help']),
        'simple_help': runner.invoke(cli, ['--help', 'simple']),
        'facter_help': runner.invoke(cli, ['--help', 'facter']),
        'device_scanner_help': runner.invoke(cli, ['--help', 'device_scanner']),
        'ip_scanner_help': runner.invoke(cli, ['--help', 'ip_scanner']),
    }
    exit_codes = set(result.exit_code for result in results.values())
    all_zero = len(exit_codes) == 1 and 0 in exit_codes
    assert all_zero


def test_device_scanner_cli():
    # runner = CliRunner()
    # results = {
    #     'main_help': runner.invoke(cli, ['device_scanner', '--help']),
    # }
    runner = CliRunner()
    result = runner.invoke(cli, ['-vvv', 'device_scanner'])
    print (result.output)
    assert result.exit_code == 0
    # assert 'Debug mode is on' in result.output
    # assert 'Syncing' in result.output
    # exit_codes = set(result.exit_code for result in results.values())
    # all_zero = len(exit_codes) == 1 and 0 in exit_codes
    # assert all_zero
