"""Policy checks wait for enrollment and preserve explicit operator choices."""
import json
from unittest.mock import Mock, call, patch

from family_vpn.addon import AddonConfiguration
from family_vpn.app import Dispatcher, Settings


def test_addon_defaults_on_and_preserves_saved_disable(tmp_path):
    (tmp_path / 'options.json').write_text('{}')
    manager = AddonConfiguration(tmp_path)
    settings = manager.load()
    assert settings.automatic
    settings.automatic = False
    manager.save_settings(settings)
    assert not manager.load().automatic
    manager.update({'reset': 'true'}, settings)
    assert settings.automatic
    assert json.loads(manager.path.read_text())['automatic']


def test_policy_interval_starts_after_registration_and_commands_still_run():
    settings = Settings(apns_key_file='synthetic', apns_key_id='synthetic', apns_team_id='synthetic', interval=1800)
    database = Mock()
    connection = database.connect.return_value.__enter__ = Mock()
    database.connect.return_value.__exit__ = Mock()
    connection.return_value.execute.return_value.fetchone.side_effect = [None, None, (1,), (1,), (1,)]
    dispatcher = Dispatcher(database, Mock(), settings, Mock())
    dispatcher.stop_event = Mock()
    dispatcher.stop_event.wait.side_effect = [False]*5 + [True]
    dispatcher.trigger = Mock()
    try:
        # Startup time is irrelevant: the clock starts at first enrollment.
        with patch('family_vpn.app.time.monotonic', side_effect=[5000, 6799, 6800]):
            dispatcher.schedule()
        assert dispatcher.trigger.call_args_list == [
            call(commands_only=True),
            call(commands_only=True),
            call(commands_only=False),
        ]
        settings.automatic = False
        dispatcher.stop_event.wait.side_effect = [False, True]
        connection.return_value.execute.return_value.fetchone.side_effect = [(1,)]
        dispatcher.trigger.reset_mock()
        dispatcher.schedule()
        dispatcher.trigger.assert_called_once_with(commands_only=True)
    finally:
        dispatcher.close()
