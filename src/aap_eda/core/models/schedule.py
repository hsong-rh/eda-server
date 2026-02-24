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

from django.db import models

from .base import BaseOrgModel, PrimordialModel


class Schedule(BaseOrgModel, PrimordialModel):
    class Meta:
        db_table = "core_schedule"
        ordering = ["id"]

    name = models.TextField(null=False)
    description = models.TextField(default="", blank=True)
    enabled = models.BooleanField(default=True)
    project = models.ForeignKey(
        "Project",
        on_delete=models.CASCADE,
        related_name="schedules",
    )
    rrule = models.TextField(
        help_text="RFC 5545 RRULE string for schedule recurrence",
    )
    next_run = models.DateTimeField(null=True, blank=True, default=None)
    last_run = models.DateTimeField(null=True, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    modified_at = models.DateTimeField(auto_now=True, null=False)

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}" f"(id={self.id}, name={self.name})>"
        )


__all__ = [
    "Schedule",
]
