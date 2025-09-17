import types
import builtins
import importlib
import sys
from unittest.mock import patch


def import_module_fresh(name: str):
    if name in sys.modules:
        del sys.modules[name]
    return importlib.import_module(name)


def test_user_in_group_true(monkeypatch):
    eu = import_module_fresh('extra-users')

    def fake_run(cmd, verbose=False, dry_run=False):
        assert cmd[:2] == ['id', '-nG']
        return 0, 'root wheel developers', ''

    with patch.object(eu, 'run', side_effect=fake_run):
        assert eu.user_in_group('alice', 'developers', verbose=False, dry_run=False) is True


def test_user_in_group_false(monkeypatch):
    eu = import_module_fresh('extra-users')

    def fake_run(cmd, verbose=False, dry_run=False):
        return 0, 'root wheel', ''

    with patch.object(eu, 'run', side_effect=fake_run):
        assert eu.user_in_group('alice', 'developers', verbose=False, dry_run=False) is False


def test_user_in_group_dry_run(monkeypatch):
    eu = import_module_fresh('extra-users')
    # Dry run should always return False to show intended actions
    assert eu.user_in_group('alice', 'developers', verbose=False, dry_run=True) is False


def test_skip_addgroup_when_already_member_on_busybox_creation(monkeypatch):
    eu = import_module_fresh('extra-users')

    # Configure environment to simulate BusyBox (adduser/addgroup present, useradd absent)
    with patch.object(eu, 'command_exists') as cmd_exists,
         patch.object(eu, 'user_exists') as user_exists,
         patch.object(eu, 'ensure_group') as ensure_group,
         patch.object(eu, 'user_in_group') as user_in_group,
         patch.object(eu, 'run') as run:

        def ce(name):
            return name in ('adduser', 'addgroup')

        cmd_exists.side_effect = ce
        user_exists.return_value = False  # user not exists yet -> creation path
        user_in_group.return_value = True  # already member, should skip addgroup

        # 'adduser -D username' gets called, skip addgroup
        def run_side_effect(cmd, verbose=False, dry_run=False):
            if cmd and cmd[0] == 'adduser':
                return 0, '', ''
            # No addgroup should be called; if it is, fail by returning non-zero
            if cmd and cmd[0] == 'addgroup':
                return 1, '', 'should not be called'
            return 0, '', ''

        run.side_effect = run_side_effect

        spec = eu.UserSpec(username='alice', group='alice', home=None, shell=None, password=None)
        eu.ensure_user(spec, create_missing_group=True, verbose=False, dry_run=False)


def test_addgroup_when_not_member_on_busybox_update(monkeypatch):
    eu = import_module_fresh('extra-users')

    # Simulate system without usermod (e.g., BusyBox), user exists, not in group
    with patch.object(eu, 'command_exists') as cmd_exists,
         patch.object(eu, 'user_exists') as user_exists,
         patch.object(eu, 'ensure_group') as ensure_group,
         patch.object(eu, 'user_in_group') as user_in_group,
         patch.object(eu, 'run') as run:

        def ce(name):
            # addgroup present, usermod absent
            return name in ('addgroup',)

        cmd_exists.side_effect = ce
        user_exists.return_value = True  # existing user path
        user_in_group.return_value = False  # not a member yet

        addgroup_called = {'value': False}

        def run_side_effect(cmd, verbose=False, dry_run=False):
            if cmd and cmd[0] == 'addgroup':
                addgroup_called['value'] = True
                return 0, '', ''
            if cmd and cmd[:2] == ['getent', 'passwd']:
                return 0, 'alice:x:1000:1000::/home/alice:/bin/sh', ''
            return 0, '', ''

        run.side_effect = run_side_effect

        spec = eu.UserSpec(username='alice', group='developers', home=None, shell=None, password=None)
        eu.ensure_user(spec, create_missing_group=True, verbose=False, dry_run=False)
        assert addgroup_called['value'] is True


