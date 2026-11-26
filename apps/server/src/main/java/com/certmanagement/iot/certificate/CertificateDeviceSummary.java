// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

/**
 * Shared by list rows and detail responses; {@code status} is null where the caller doesn't need it.
 *
 * <p>{@code archived} is carried separately from {@code status} because the two answer different
 * questions: status is the device's lifecycle in its source, archived is whether an operator took it
 * out of the inventory. A certificate on an archived device is still attributed to that device, and
 * saying so is the difference between "this device was put away" and "we cannot tell whose
 * credential this is" — the second is a thing operators chase.
 */
public record CertificateDeviceSummary(
        String deviceXref, String deviceName, String status, boolean archived) {
}
