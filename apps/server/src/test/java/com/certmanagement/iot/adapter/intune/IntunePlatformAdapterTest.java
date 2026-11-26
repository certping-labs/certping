// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.adapter.intune;

import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceClass;
import com.certmanagement.iot.enums.DeviceFacet;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IntunePlatformAdapterTest {
    private static final String ZERO_GUID = "00000000-0000-0000-0000-000000000000";
    private final IntunePlatformAdapter adapter = new IntunePlatformAdapter(new DeviceFieldNormalizer());

    @Test
    void declaresItsProviderAndNonPiiFacets() {
        assertThat(adapter.getProvider()).isEqualTo(DeviceSourceProvider.INTUNE);
        assertThat(adapter.deviceClass()).isEqualTo(DeviceClass.MANAGED_ENDPOINT);
        assertThat(adapter.facets()).containsExactly(DeviceFacet.ENDPOINT_POSTURE);
    }

    @Test
    void storesProviderIdentifiersInsideTheDeviceRow() {
        assertThat(adapter.sourceIdentifiers(payload("obj-1", "dev-1", null)))
                .containsEntry("entraObjectId", "obj-1")
                .containsEntry("entraDeviceId", "dev-1");
    }

    @Test
    void dropsZeroAndBlankProviderIdentifiers() {
        assertThat(adapter.sourceIdentifiers(payload(ZERO_GUID, ZERO_GUID, null))).isEmpty();
        assertThat(adapter.sourceIdentifiers(payload(" ", null, null))).isEmpty();
    }

    @Test
    void mapsComplianceWithoutFailingOnFutureValues() {
        assertThat(adapter.mapCompliance("compliant")).isEqualTo(ComplianceState.COMPLIANT);
        assertThat(adapter.mapCompliance("noncompliant")).isEqualTo(ComplianceState.NON_COMPLIANT);
        assertThat(adapter.mapCompliance("inGracePeriod")).isEqualTo(ComplianceState.IN_GRACE);
        assertThat(adapter.mapCompliance("someFutureState")).isEqualTo(ComplianceState.UNKNOWN);
        assertThat(adapter.mapCompliance(null)).isNull();
    }

    private static DeviceIdentityPayload payload(
            String entraObjectId, String entraDeviceId, String complianceState) {
        return new DeviceIdentityPayload(
                "managed-device-1", entraObjectId, entraDeviceId, "serial-1",
                null, null, null, null, null, null, null, null,
                null, null, null, null,
                complianceState, null, null, null, null, null, null, null,
                null, null, null, null, null);
    }
}
