// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.enums;

/**
 * Device management platform a sync command targets.
 *
 * <p>Mirrors {@code iot_device_source.provider} on the server. Only the values a
 * connector exists for are ever dispatched; the rest are accepted by the schema but rejected
 * before a command is published.
 */
public enum DevicePlatformType {
    INTUNE,
    JAMF,
    WORKSPACE_ONE,
    AWS_IOT,
    AZURE_IOT;

    /** Returns null for an unknown or missing value rather than guessing. */
    public static DevicePlatformType fromString(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
