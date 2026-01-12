#  Copyright 2025 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Tests for dispatcherctl debug command."""

import io

import pytest
from django.core.management.base import CommandError

from aap_eda.core.management.commands import dispatcherctl


@pytest.fixture(autouse=True)
def clear_dispatcher_env(monkeypatch, mocker):
    monkeypatch.delenv("DISPATCHERD_CONFIG_FILE", raising=False)
    mocker.patch.object(
        dispatcherctl, "connection", mocker.Mock(vendor="postgresql")
    )


def test_command_init_calls_startup_logging(mocker):
    mocker.patch.object(dispatcherctl, "startup_logging")
    dispatcherctl.Command()
    dispatcherctl.startup_logging.assert_called_once()


def test_dispatcherctl_runs_control_with_generated_config(mocker):
    command = dispatcherctl.Command()
    command.stdout = io.StringIO()

    data = {"foo": "bar"}
    mocker.patch.object(
        dispatcherctl, "_build_command_data_from_args", return_value=data
    )
    dispatcher_setup = mocker.patch.object(dispatcherctl, "dispatcherd_setup")
    mocker.patch.object(
        dispatcherctl.settings,
        "DISPATCHERD_DEFAULT_SETTINGS",
        {"setting": "value"},
    )

    control = mocker.Mock()
    control.control_with_reply.return_value = [{"status": "ok"}]
    mocker.patch.object(
        dispatcherctl, "get_control_from_settings", return_value=control
    )
    mocker.patch.object(dispatcherctl.yaml, "dump", return_value="payload\n")

    command.handle(
        command="running",
        config=dispatcherctl.DEFAULT_CONFIG_FILE,
        expected_replies=1,
    )

    dispatcher_setup.assert_called_once_with({"setting": "value"})
    control.control_with_reply.assert_called_once_with(
        "running", data=data, expected_replies=1
    )
    assert command.stdout.getvalue() == "payload\n"


def test_dispatcherctl_rejects_custom_config_path():
    command = dispatcherctl.Command()

    with pytest.raises(CommandError):
        command.handle(
            command="running",
            config="/tmp/dispatcher.yml",
            expected_replies=1,
        )


def test_dispatcherctl_rejects_sqlite_db(mocker):
    command = dispatcherctl.Command()
    mocker.patch.object(dispatcherctl, "connection", mocker.Mock(vendor="sqlite"))

    with pytest.raises(CommandError, match="sqlite3"):
        command.handle(
            command="running",
            config=dispatcherctl.DEFAULT_CONFIG_FILE,
            expected_replies=1,
        )


def test_dispatcherctl_raises_when_replies_missing(mocker):
    command = dispatcherctl.Command()
    command.stdout = io.StringIO()

    mocker.patch.object(
        dispatcherctl, "_build_command_data_from_args", return_value={}
    )
    mocker.patch.object(dispatcherctl, "dispatcherd_setup")
    mocker.patch.object(
        dispatcherctl.settings, "DISPATCHERD_DEFAULT_SETTINGS", {}
    )
    control = mocker.Mock()
    control.control_with_reply.return_value = [{"status": "ok"}]
    mocker.patch.object(
        dispatcherctl, "get_control_from_settings", return_value=control
    )
    mocker.patch.object(
        dispatcherctl.yaml, "dump", return_value="- status: ok\n"
    )

    with pytest.raises(CommandError):
        command.handle(
            command="running",
            config=dispatcherctl.DEFAULT_CONFIG_FILE,
            expected_replies=2,
        )

    control.control_with_reply.assert_called_once_with(
        "running", data={}, expected_replies=2
    )


def test_dispatcherctl_requires_command():
    command = dispatcherctl.Command()

    with pytest.raises(CommandError, match="No dispatcher control command"):
        command.handle(
        command=None,
        config=dispatcherctl.DEFAULT_CONFIG_FILE,
        expected_replies=1,
    )
