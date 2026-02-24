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

from rest_framework import serializers

from aap_eda.core import models
from aap_eda.core.utils.rrule import compute_next_run, validate_rrule


class ScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Schedule
        read_only_fields = [
            "id",
            "next_run",
            "last_run",
            "created_at",
            "modified_at",
        ]
        fields = [
            "name",
            "description",
            "enabled",
            "rrule",
            "project_id",
            "organization_id",
            *read_only_fields,
        ]

    def validate_rrule(self, value):
        try:
            validate_rrule(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))
        return value


class ScheduleCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Schedule
        fields = [
            "name",
            "description",
            "enabled",
            "rrule",
        ]

    def validate_rrule(self, value):
        try:
            validate_rrule(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))
        return value

    def create(self, validated_data):
        rrule_str = validated_data.get("rrule", "")
        if validated_data.get("enabled", True):
            validated_data["next_run"] = compute_next_run(rrule_str)
        return super().create(validated_data)


class ScheduleUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Schedule
        fields = [
            "name",
            "description",
            "enabled",
            "rrule",
        ]

    name = serializers.CharField(required=False)
    rrule = serializers.CharField(required=False)

    def validate_rrule(self, value):
        try:
            validate_rrule(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))
        return value

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        if instance.enabled:
            rrule_str = instance.rrule
            instance.next_run = compute_next_run(rrule_str)
        else:
            instance.next_run = None
        instance.save(update_fields=["next_run"])
        return instance
