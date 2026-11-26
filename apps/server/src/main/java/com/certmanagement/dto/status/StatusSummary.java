// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.status;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** A subset of the Statuspage v2 {@code summary.json} document. Every value is fixed or a check time. */
public record StatusSummary(
        Page page,
        Indicator status,
        List<Component> components,
        List<Object> incidents,
        @JsonProperty("scheduled_maintenances") List<Object> scheduledMaintenances) {

    public record Page(@JsonProperty("updated_at") String updatedAt) {}

    public record Indicator(String indicator, String description) {}

    public record Component(String id, String name, String status, @JsonProperty("updated_at") String updatedAt) {}
}
