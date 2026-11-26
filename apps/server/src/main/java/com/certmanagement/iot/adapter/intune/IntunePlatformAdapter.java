// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.adapter.intune;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceClass;
import com.certmanagement.iot.enums.DeviceFacet;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Microsoft Intune. Devices arrive as managed endpoints with posture and no owner PII. */
@Component
@RequiredArgsConstructor
public class IntunePlatformAdapter implements PlatformAdapter {

    private static final Set<String> PROVIDER_ATTRIBUTE_KEYS = Set.of(
            "managementState", "easActivated", "azureADRegistered", "deviceCategory",
            "enrollmentProfileName", "exchangeAccessState", "exchangeAccessStateReason",
            "partnerReportedThreatState", "requireUserEnrollmentApproval",
            "managementCertificateExpiresAt", "complianceGracePeriodExpiresAt",
            "androidSecurityPatchLevel");

    private final DeviceFieldNormalizer normalizer;

    @Override
    public DeviceSourceProvider getProvider() {
        return DeviceSourceProvider.INTUNE;
    }

    /**
     * The two Entra identifiers, when the device has them.
     *
     * <p>Both are passed through {@code guid()}: an all-zero {@code azureADDeviceId} means the
     * device is not Entra-registered rather than that it has that id, and it was observed on a
     * live tenant. Storing it would attach one shared key to every unregistered device, and the
     * value would pollute every unregistered device's secondary identifier metadata.
     */
    @Override
    public Map<String, String> sourceIdentifiers(DeviceIdentityPayload payload) {
        Map<String, String> identifiers = new LinkedHashMap<>();
        String entraObjectId = normalizer.guid(payload.entraObjectId());
        if (entraObjectId != null) {
            identifiers.put("entraObjectId", entraObjectId);
        }
        String entraDeviceId = normalizer.guid(payload.entraDeviceId());
        if (entraDeviceId != null) {
            identifiers.put("entraDeviceId", entraDeviceId);
        }
        return identifiers;
    }

    @Override
    public DeviceClass deviceClass() {
        return DeviceClass.MANAGED_ENDPOINT;
    }

    @Override
    public Set<DeviceFacet> facets() {
        return EnumSet.of(DeviceFacet.ENDPOINT_POSTURE);
    }

    @Override
    public Set<String> providerAttributeKeys() {
        return PROVIDER_ATTRIBUTE_KEYS;
    }

    /**
     * Graph's {@code complianceState}: compliant, noncompliant, conflict, error, inGracePeriod,
     * configManager, unknown.
     *
     * <p>{@code conflict}, {@code error} and {@code configManager} collapse to UNKNOWN — none is
     * a compliance verdict, and treating them as NON_COMPLIANT would block issuance on what is
     * really a reporting gap. The vendor's own wording is kept in {@code compliance_state_raw}.
     */
    @Override
    public ComplianceState mapCompliance(String raw) {
        String normalized = normalizer.text(raw);
        if (normalized == null) {
            return null;
        }
        String key = normalized.trim().toLowerCase().replace(" ", "").replace("_", "");
        return switch (key) {
            case "compliant" -> ComplianceState.COMPLIANT;
            case "noncompliant", "non-compliant", "notcompliant" -> ComplianceState.NON_COMPLIANT;
            case "ingraceperiod", "ingrace", "graceperiod" -> ComplianceState.IN_GRACE;
            case "unknown", "conflict", "error", "configmanager" -> ComplianceState.UNKNOWN;
            default -> {
                try {
                    yield ComplianceState.valueOf(normalized.trim().toUpperCase().replace('-', '_'));
                } catch (IllegalArgumentException ex) {
                    yield ComplianceState.UNKNOWN;
                }
            }
        };
    }
}
