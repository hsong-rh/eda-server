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

from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from aap_eda.api import exceptions as api_exc
from aap_eda.api.serializers.schedule import (
    ScheduleCreateSerializer,
    ScheduleSerializer,
    ScheduleUpdateSerializer,
)
from aap_eda.core import models

logger = logging.getLogger(__name__)


@extend_schema_view(
    list=extend_schema(
        description="List schedules for a project",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                ScheduleSerializer(many=True),
                description="Return a list of schedules.",
            ),
        },
    ),
)
class ProjectScheduleViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """Schedules nested under a project."""

    serializer_class = ScheduleSerializer

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        return models.Schedule.objects.filter(project_id=project_id).order_by(
            "id"
        )

    @extend_schema(
        description="Create a schedule for a project",
        request=ScheduleCreateSerializer,
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                ScheduleSerializer,
                description="Return the created schedule.",
            ),
        },
    )
    def create(self, request, project_id=None):
        try:
            project = models.Project.objects.get(pk=project_id)
        except models.Project.DoesNotExist:
            raise api_exc.NotFound(
                f"Project with ID={project_id} " "does not exist."
            )

        # Manual SCM projects cannot have schedules
        if not project.scm_type:
            raise api_exc.Conflict(
                detail="Manual projects cannot have" " schedules."
            )

        serializer = ScheduleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        schedule = serializer.save(
            project=project,
            organization=project.organization,
        )
        return Response(
            ScheduleSerializer(schedule).data,
            status=status.HTTP_201_CREATED,
        )


@extend_schema_view(
    retrieve=extend_schema(
        description="Get a schedule by id",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                ScheduleSerializer,
                description="Return a schedule.",
            ),
        },
    ),
    destroy=extend_schema(
        description="Delete a schedule by id",
        responses={
            status.HTTP_204_NO_CONTENT: OpenApiResponse(
                None,
                description="Delete successful.",
            ),
        },
    ),
)
class ScheduleViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Individual schedule CRUD."""

    queryset = models.Schedule.objects.order_by("id")
    serializer_class = ScheduleSerializer

    @extend_schema(
        description="Partial update of a schedule",
        request=ScheduleUpdateSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                ScheduleSerializer,
                description="Return the updated schedule.",
            ),
        },
    )
    def partial_update(self, request, *args, **kwargs):
        schedule = self.get_object()
        serializer = ScheduleUpdateSerializer(
            instance=schedule,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        schedule = serializer.save()
        return Response(
            ScheduleSerializer(schedule).data,
        )
