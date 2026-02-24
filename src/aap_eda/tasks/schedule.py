#  Copyright 2024 Red Hat, Inc.
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

import logging

from ansible_base.lib.utils.db import advisory_lock
from django.utils import timezone

from aap_eda.core import models
from aap_eda.core.utils.rrule import compute_next_run
from aap_eda.tasks.project import sync_project

logger = logging.getLogger(__name__)


def check_due_schedules():
    """Check for due project schedules and trigger syncs.

    Runs periodically via dispatcherd. Uses an advisory lock
    to prevent concurrent execution across workers.
    """
    with advisory_lock("check_due_schedules", wait=False) as acquired:
        if not acquired:
            logger.debug(
                "Another task already running " "check_due_schedules, exiting"
            )
            return
        _check_due_schedules()


def _check_due_schedules():
    """Process all due schedules."""
    now = timezone.now()
    due_schedules = models.Schedule.objects.filter(
        enabled=True,
        next_run__lte=now,
    ).select_related("project")

    triggered = 0
    skipped = 0
    for schedule in due_schedules:
        project = schedule.project

        # Skip projects already syncing
        if project.import_state in [
            models.Project.ImportState.PENDING,
            models.Project.ImportState.RUNNING,
        ]:
            logger.debug(
                "Skipping schedule '%s' - project '%s' " "already syncing",
                schedule.name,
                project.name,
            )
            skipped += 1
            continue

        # Skip manual projects (should not have schedules,
        # but defensive check)
        if not project.scm_type:
            logger.warning(
                "Schedule '%s' attached to manual " "project '%s' - skipping",
                schedule.name,
                project.name,
            )
            skipped += 1
            continue

        try:
            sync_project(project.id)
            triggered += 1
            logger.info(
                "Triggered sync for project '%s' " "via schedule '%s'",
                project.name,
                schedule.name,
            )
        except Exception as e:
            logger.error(
                "Failed to trigger sync for project "
                "'%s' via schedule '%s': %s",
                project.name,
                schedule.name,
                e,
                exc_info=True,
            )

        # Update schedule timestamps
        schedule.last_run = now
        try:
            schedule.next_run = compute_next_run(schedule.rrule, after=now)
        except Exception:
            logger.error(
                "Failed to compute next_run for " "schedule '%s', disabling",
                schedule.name,
                exc_info=True,
            )
            schedule.enabled = False
            schedule.next_run = None

        schedule.save(
            update_fields=[
                "last_run",
                "next_run",
                "enabled",
            ]
        )

    if triggered or skipped:
        logger.info(
            "Schedule check complete: %d triggered, " "%d skipped",
            triggered,
            skipped,
        )
