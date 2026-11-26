// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

/** Statuspage component states this service reports, declared from least to most severe. */
public enum ComponentStatus {

    OPERATIONAL("operational", "none", "All systems operational"),
    DEGRADED_PERFORMANCE("degraded_performance", "minor", "Minor service disruption"),
    PARTIAL_OUTAGE("partial_outage", "major", "Partial system outage"),
    MAJOR_OUTAGE("major_outage", "critical", "Major system outage");

    private final String value;
    private final String indicator;
    private final String description;

    ComponentStatus(String value, String indicator, String description) {
        this.value = value;
        this.indicator = indicator;
        this.description = description;
    }

    public String value() {
        return value;
    }

    /** The page indicator when this is the worst component state. */
    public String indicator() {
        return indicator;
    }

    public String description() {
        return description;
    }

    ComponentStatus atLeast(ComponentStatus floor) {
        return compareTo(floor) >= 0 ? this : floor;
    }
}
