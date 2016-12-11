import os
import pytest
from pyethapp import app
from pyethapp import config
from click.testing import CliRunner

genesis_json = {
    "nonce": "0x00000000000000ff",
    "difficulty": "0xff0000000",
    "mixhash": "0xff00000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0xff00000000000000000000000000000000000000",
    "timestamp": "0xff",
    "parentHash": "0xff00000000000000000000000000000000000000000000000000000000000000",
    "extraData": "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
    "gasLimit": "0xffff",
    "alloc": {
        "ffffffffffffffffffffffffffffffffffffffff": {"balance": "9876543210"},
        "0000000000000000000000000000000000000000": {"balance": "1234567890"}
    }
}

genesis_yaml = """
eth:
  genesis: {}
""".format(genesis_json)


def test_show_usage():
    runner = CliRunner()
    result = runner.invoke(app.app, [])
    assert "Usage: app " in result.output, result.output


def test_no_such_option():
    runner = CliRunner()
    result = runner.invoke(app.app, ['--WTF'])
    assert 'no such option: --WTF' in result.output, result.output


def test_no_such_command():
    runner = CliRunner()
    result = runner.invoke(app.app, ['eat'])
    assert 'Error: No such command "eat"' in result.output, result.output


@pytest.mark.parametrize('content', ['', '<html/>', 'print "hello world"'])
def test_non_dict_yaml_as_config_file(content):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as text_file:
            text_file.write(content)

        result = runner.invoke(app.app, ['-C', 'config.yaml'])
        assert 'content of config should be an yaml dictionary' in result.output, result.output


@pytest.mark.parametrize('param', [('--Config', 'myconfig.yaml'),
                                   ('-C', 'myconfig.yaml'),
                                   ('-c', 'mygenesis.json'),
                                   ('-c', 'dict')])
def test_custom_config_file(param):
    runner = CliRunner()
    with runner.isolated_filesystem():
        opt, arg = param

        if arg.endswith('.yaml'):
            with open(arg, 'w') as text_file:
                text_file.write(genesis_yaml)
        elif arg.endswith('.json'):
            with open(arg, 'w') as text_file:
                text_file.write(str(genesis_json))
        else:
            arg = str(genesis_json).replace('\n', '').replace(' ', '')

        if opt == '-c':
            arg = 'eth.genesis={}'.format(arg)

        result = runner.invoke(app.app, [opt, arg, 'config'])

        if arg.endswith('.json'):
            patterns = ['genesis: {}'.format(param[1])]
        else:
            patterns = ["{}: '{}'".format(k, v) for k, v in genesis_json.items() if k != 'alloc']

        for pat in patterns:
            assert pat in result.output, '`{}` not found'.format(pat)

        for k, v in genesis_json['alloc'].items():
            assert k in result.output
            assert v['balance'] in result.output


def test_config_from_datadir(tmpdir):
    """Test, that when given a `--data-dir`, the app
    reads the config from the '`--data-dir`/config.yaml'.
    """
    DIR = "datadir"
    runner = CliRunner()
    with runner.isolated_filesystem():
        os.mkdir(DIR)
        runner.invoke(app.app, ["--data-dir", DIR, "config"])
        with open(os.path.join(DIR, config.CONFIG_FILE_NAME), "w") as configfile:
            configfile.write("p2p:\n  max_peers: 9000")
        result = runner.invoke(app.app, ["--data-dir", DIR, "config"])
        assert "max_peers: 9000" in result.output


if __name__ == '__main__':
    test_show_usage()
    test_no_such_option()
    test_no_such_command()
    test_non_dict_yaml_as_config_file('')
    test_non_dict_yaml_as_config_file('<html/>')
    test_non_dict_yaml_as_config_file('print "hello world"')
    test_custom_config_file(('--Config', 'myconfig.yaml'))
    test_custom_config_file(('-C', 'myconfig.yaml'))
    test_custom_config_file(('-c', 'mygenesis.json'))
    test_custom_config_file(('-c', 'dict'))
