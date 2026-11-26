// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.enums;

/**
 * Hardware class of a cloud-IoT device.
 *
 * <p>Not cosmetic: an MPU gateway renews its own certificates and keeps a clock, an MCU sensor
 * often does neither. Both are CONNECTED_THING, so {@code DeviceClass} cannot express the
 * difference and certificate policy later depends on it.
 */
public enum ThingFormFactor {
    /** Microcontroller — constrained, frequently no clock and no self-renewal. */
    MCU,
    /** Microprocessor — general-purpose, renews normally. */
    MPU,
    /** Brokers identity for devices behind it. */
    GATEWAY
}
