#  Copyright 2023 Red Hat, Inc.
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

import django_filters

from aap_eda.core import models


class RulebookFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(
        field_name="name",
        lookup_expr="icontains",
        label="Filter by rulebook name.",
    )

    project_id = django_filters.NumberFilter(
        field_name="project_id",
        lookup_expr="exact",
        label="Filter by rulebook's project id.",
    )

    class Meta:
        model = models.Rulebook
        fields = ["name", "project_id"]


class RulesetFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(
        field_name="name",
        lookup_expr="istartswith",
        label="Filter by ruleset name.",
    )

    class Meta:
        model = models.Ruleset
        fields = ["name"]


class AuditRuleFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(
        field_name="name",
        lookup_expr="istartswith",
        label="Filter by rule audit name.",
    )

    class Meta:
        model = models.AuditRule
        fields = ["name"]


class AuditRuleActionFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(
        field_name="name",
        lookup_expr="istartswith",
        label="Filter by rule audit action name.",
    )

    class Meta:
        model = models.AuditAction
        fields = ["name"]


class AuditRuleEventFilter(django_filters.FilterSet):
    source_name = django_filters.CharFilter(
        field_name="source_name",
        lookup_expr="istartswith",
        label="Filter by rule audit event source name.",
    )

    class Meta:
        model = models.AuditEvent
        fields = ["source_name"]
