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

"""Dispatcherctl management command for debug tools."""

import argparse
import inspect
import logging
import os

import yaml
from dispatcherd.cli import (
    CONTROL_ARG_SCHEMAS,
    DEFAULT_CONFIG_FILE,
    _base_cli_parent,
    _build_command_data_from_args,
    _control_common_parent,
    _register_control_arguments,
)
from dispatcherd.config import setup as dispatcherd_setup
from dispatcherd.factories import get_control_from_settings
from dispatcherd.service import control_tasks
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection

from aap_eda.utils.logging import startup_logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Dispatcherctl management command for debug tools."""

    help = "Dispatcherctl management command for debug tools"

    def __init__(self, *args, **kwargs):
        """Initialize command and perform startup logging."""
        super().__init__(*args, **kwargs)
        # Perform startup logging when command is instantiated
        startup_logging(logger)

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command line arguments for debug commands."""
        parser.description = (
            "Run dispatcherd control commands using aap-eda-manage."
        )
        base_parent = _base_cli_parent()
        control_parent = _control_common_parent()
        parser._add_container_actions(base_parent)
        parser._add_container_actions(control_parent)

        subparsers = parser.add_subparsers(dest="command", metavar="command")
        subparsers.required = True
        shared_parents = [base_parent, control_parent]
        for command in control_tasks.__all__:
            func = getattr(control_tasks, command, None)
            doc = inspect.getdoc(func) or ""
            summary = doc.splitlines()[0] if doc else None
            command_parser = subparsers.add_parser(
                command,
                help=summary,
                description=doc,
                parents=shared_parents,
            )
            _register_control_arguments(
                command_parser, CONTROL_ARG_SCHEMAS.get(command)
            )

    def handle(self, *args, **options) -> None:
        """Handle dispatcherctl debug command routing."""
        command = options.get("command")
        if not command:
            raise CommandError("No dispatcher control command specified")

        for django_opt in (
            "verbosity",
            "traceback",
            "no_color",
            "force_color",
            "skip_checks",
        ):
            options.pop(django_opt, None)

        config_path = os.path.abspath(
            options.pop("config", DEFAULT_CONFIG_FILE)
        )
        expected_replies = options.pop("expected_replies", 1)

        env_config = os.getenv("DISPATCHERD_CONFIG_FILE")
        default_config = os.path.abspath(DEFAULT_CONFIG_FILE)
        if config_path != default_config:
            raise CommandError(
                "The config path CLI option is not allowed for the "
                "aap-eda-manage command"
            )
        if connection.vendor == "sqlite":
            raise CommandError(
                "dispatcherctl is not supported with sqlite3; use a "
                "PostgreSQL database"
            )
        elif env_config:
            logger.warning(
                "Using config from environment variable "
                f"DISPATCHERD_CONFIG_FILE={env_config}"
            )
            dispatcherd_setup()
        else:
            logger.info(
                "Using config generated from "
                "settings.DISPATCHERD_DEFAULT_SETTINGS"
            )
            dispatcherd_setup(settings.DISPATCHERD_DEFAULT_SETTINGS)

        schema_namespace = argparse.Namespace(**options)
        data = _build_command_data_from_args(schema_namespace, command)

        ctl = get_control_from_settings()
        returned = ctl.control_with_reply(
            command, data=data, expected_replies=expected_replies
        )
        self.stdout.write(yaml.dump(returned, default_flow_style=False))
        if len(returned) < expected_replies:
            logger.error(
                f"Obtained only {len(returned)} of {expected_replies}"
            )
            raise CommandError(
                "dispatcherctl returned fewer replies than expected"
            )
