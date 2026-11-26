// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.adapter;

import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceClass;
import com.certmanagement.iot.enums.DeviceFacet;
import com.certmanagement.iot.enums.DeviceSourceProvider;

import java.util.Map;
import java.util.Set;

/**
 * Per-platform mapping rules for the identity upsert engine.
 *
 * <p>Everything a device's shape depends on is decided here rather than in
 * {@code IotIdentityRegistrationService}, so adding Jamf, Workspace ONE or AWS IoT is a new
 * implementation of this interface and nothing else. Implementations are Spring beans, collected
 * by {@link PlatformAdapterFactory}.
 *
 * <p><b>Mapping only, no persistence.</b> Adapters decide <em>what</em> a device is; the service
 * owns the repositories and decides <em>how</em> it is written. That keeps transaction handling
 * and the change-detection diff in one place instead of duplicated per platform.
 *
 * <p>The primary device id remains scoped to its source row. Secondary provider identifiers are
 * stored as JSON for future correlation, not as identity-defining cross-reference rows.
 */
public interface PlatformAdapter {

    /** The platform this adapter maps. One adapter per value. */
    DeviceSourceProvider getProvider();

    /**
     * Additional identifiers this source knows the device by, beyond the primary.
     *
     * <p>Intune contributes the two Entra ids; a platform with no secondary identity returns an
     * empty list. Values must already be normalised — a null or blank value is dropped by the
     * caller rather than stored.
     */
    Map<String, String> sourceIdentifiers(DeviceIdentityPayload payload);

    /** Display hint for devices from this source. Advisory: facets are the real structure. */
    DeviceClass deviceClass();

    /** Detail tables devices from this source can populate. */
    Set<DeviceFacet> facets();

    /** Provider metadata keys the server may persist after scalar and length validation. */
    Set<String> providerAttributeKeys();

    /**
     * Maps the source's compliance vocabulary onto {@link ComplianceState}.
     *
     * <p>Returns null when the source reports nothing. Unrecognised values should map to
     * {@link ComplianceState#UNKNOWN} rather than throwing: vendors add values without notice,
     * and a sync must not fail at 3am because of one.
     */
    ComplianceState mapCompliance(String raw);
}
