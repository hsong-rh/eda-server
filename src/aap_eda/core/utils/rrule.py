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

from datetime import datetime
from typing import Optional

from dateutil.rrule import rrulestr
from django.utils import timezone


def validate_rrule(rrule_string: str) -> None:
    """Validate an RRULE string.

    Raises ValueError if the string is not a valid RFC 5545 RRULE.
    """
    try:
        rrulestr(rrule_string)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid RRULE: {e}") from e


def compute_next_run(
    rrule_string: str,
    after: Optional[datetime] = None,
) -> Optional[datetime]:
    """Compute the next occurrence after the given time.

    Returns None if there are no future occurrences.
    """
    if after is None:
        after = timezone.now()
    rule = rrulestr(rrule_string)
    next_dt = rule.after(after, inc=False)
    if next_dt is None:
        return None
    if timezone.is_naive(next_dt):
        next_dt = timezone.make_aware(next_dt)
    return next_dt
