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

from datetime import datetime, timezone

import pytest

from aap_eda.core.utils.rrule import compute_next_run, validate_rrule


class TestValidateRrule:
    def test_valid_rrule(self):
        validate_rrule(
            "DTSTART:20260101T000000Z\n" "RRULE:FREQ=DAILY;INTERVAL=1"
        )

    def test_valid_hourly(self):
        validate_rrule(
            "DTSTART:20260101T000000Z\n" "RRULE:FREQ=HOURLY;INTERVAL=2"
        )

    def test_invalid_rrule(self):
        with pytest.raises(ValueError, match="Invalid RRULE"):
            validate_rrule("not-a-valid-rrule")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            validate_rrule("")


class TestComputeNextRun:
    def test_next_run_daily(self):
        after = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = compute_next_run(
            "DTSTART:20260101T000000Z\n" "RRULE:FREQ=DAILY;INTERVAL=1",
            after=after,
        )
        assert result is not None
        assert result > after

    def test_next_run_hourly(self):
        after = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = compute_next_run(
            "DTSTART:20260101T000000Z\n" "RRULE:FREQ=HOURLY;INTERVAL=1",
            after=after,
        )
        assert result is not None
        assert result == datetime(2026, 1, 1, 13, 0, 0, tzinfo=timezone.utc)

    def test_finite_rrule_past_end(self):
        after = datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = compute_next_run(
            "DTSTART:20260101T000000Z\n" "RRULE:FREQ=DAILY;COUNT=3",
            after=after,
        )
        assert result is None
