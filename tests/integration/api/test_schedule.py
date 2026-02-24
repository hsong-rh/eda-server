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

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from aap_eda.core import models
from tests.integration.constants import api_url_v1

RRULE = "DTSTART:20260101T000000Z\nRRULE:FREQ=DAILY;INTERVAL=1"


@pytest.fixture
def git_project(default_organization):
    return models.Project.objects.create(
        name="test-git-project",
        url="https://git.example.com/repo.git",
        scm_type="git",
        organization=default_organization,
        import_state=models.Project.ImportState.COMPLETED,
        git_hash="abc123",
    )


@pytest.fixture
def schedule(git_project, default_organization):
    return models.Schedule.objects.create(
        name="daily-sync",
        rrule=RRULE,
        project=git_project,
        organization=default_organization,
    )


# Test: List schedules for a project
@pytest.mark.django_db
def test_list_project_schedules(
    admin_client: APIClient,
    git_project: models.Project,
    schedule: models.Schedule,
):
    response = admin_client.get(
        f"{api_url_v1}/projects/{git_project.id}/schedules/"
    )
    assert response.status_code == status.HTTP_200_OK
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["name"] == "daily-sync"
    assert results[0]["rrule"] == RRULE
    assert results[0]["enabled"] is True


# Test: Create schedule for a project
@pytest.mark.django_db
def test_create_project_schedule(
    admin_client: APIClient,
    git_project: models.Project,
):
    body = {
        "name": "hourly-sync",
        "rrule": ("DTSTART:20260101T000000Z\n" "RRULE:FREQ=HOURLY;INTERVAL=1"),
    }
    response = admin_client.post(
        f"{api_url_v1}/projects/{git_project.id}/schedules/",
        data=body,
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["name"] == "hourly-sync"
    assert data["enabled"] is True
    assert data["next_run"] is not None
    assert data["project_id"] == git_project.id


# Test: Create schedule with invalid RRULE
@pytest.mark.django_db
def test_create_schedule_invalid_rrule(
    admin_client: APIClient,
    git_project: models.Project,
):
    body = {
        "name": "bad-schedule",
        "rrule": "not-a-valid-rrule",
    }
    response = admin_client.post(
        f"{api_url_v1}/projects/{git_project.id}/schedules/",
        data=body,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


# Test: Create schedule for non-existent project
@pytest.mark.django_db
def test_create_schedule_nonexistent_project(
    admin_client: APIClient,
):
    body = {"name": "orphan", "rrule": RRULE}
    response = admin_client.post(
        f"{api_url_v1}/projects/99999/schedules/",
        data=body,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


# Test: Retrieve schedule by id
@pytest.mark.django_db
def test_retrieve_schedule(
    admin_client: APIClient,
    schedule: models.Schedule,
):
    response = admin_client.get(f"{api_url_v1}/schedules/{schedule.id}/")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "daily-sync"


# Test: Partial update schedule
@pytest.mark.django_db
def test_partial_update_schedule(
    admin_client: APIClient,
    schedule: models.Schedule,
):
    response = admin_client.patch(
        f"{api_url_v1}/schedules/{schedule.id}/",
        data={"enabled": False},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["enabled"] is False
    assert data["next_run"] is None


# Test: Delete schedule
@pytest.mark.django_db
def test_delete_schedule(
    admin_client: APIClient,
    schedule: models.Schedule,
):
    response = admin_client.delete(f"{api_url_v1}/schedules/{schedule.id}/")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not models.Schedule.objects.filter(id=schedule.id).exists()


# Test: Cascade delete (project deleted -> schedules deleted)
@pytest.mark.django_db
def test_cascade_delete_schedules(
    git_project: models.Project,
    schedule: models.Schedule,
):
    schedule_id = schedule.id
    git_project.delete()
    assert not models.Schedule.objects.filter(id=schedule_id).exists()


# Test: Manual project cannot have schedules
@pytest.mark.django_db
def test_manual_project_no_schedules(
    admin_client: APIClient,
    default_organization,
):
    manual_project = models.Project.objects.create(
        name="manual-project",
        url="",
        scm_type="",
        organization=default_organization,
        import_state=models.Project.ImportState.COMPLETED,
        git_hash="",
    )
    body = {"name": "should-fail", "rrule": RRULE}
    response = admin_client.post(
        f"{api_url_v1}/projects/" f"{manual_project.id}/schedules/",
        data=body,
    )
    assert response.status_code == status.HTTP_409_CONFLICT
