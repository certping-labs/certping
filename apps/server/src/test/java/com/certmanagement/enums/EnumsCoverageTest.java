// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Compact coverage for the simple/value-carrying enums in {@code com.certmanagement.enums}.
 * Exercises values()/valueOf() round trips plus every custom field, accessor and helper method.
 */
class EnumsCoverageTest {

    private static <E extends Enum<E>> void roundTrip(Class<E> type) {
        E[] constants = type.getEnumConstants();
        assertThat(constants).isNotEmpty();
        for (E c : constants) {
            assertThat(Enum.valueOf(type, c.name())).isSameAs(c);
            assertThat(c.ordinal()).isGreaterThanOrEqualTo(0);
        }
    }

    @Test
    void plainEnumsRoundTrip() {
        roundTrip(CertEventType.class);
        roundTrip(CertificateStatus.class);
        roundTrip(AgentDeepHealthCheckStatus.class);
        roundTrip(DeploymentStatus.class);
        roundTrip(CaProvider.class);
        roundTrip(AgentHealthOverallStatus.class);
        roundTrip(AgentDeepHealthMetricStatus.class);
        roundTrip(RenewalStatus.class);
        roundTrip(CertType.class);
    }



    @Test
    void alertStatus() {
        assertThat(AlertStatus.NEW.getValue()).isEqualTo("new");
        assertThat(AlertStatus.RENEWAL_FAILED.getDisplayName()).isEqualTo("Renewal Failed");
        for (AlertStatus s : AlertStatus.values()) {
            assertThat(s.getValue()).isNotBlank();
            assertThat(s.getDisplayName()).isNotBlank();
        }
    }

    @Test
    void alertSeverity() {
        assertThat(AlertSeverity.CRITICAL.getValue()).isEqualTo("critical");
        assertThat(AlertSeverity.INFO.getDisplayName()).isEqualTo("Info");
        for (AlertSeverity s : AlertSeverity.values()) {
            assertThat(s.getValue()).isNotBlank();
            assertThat(s.getDisplayName()).isNotBlank();
        }
    }

    @Test
    void alertTypeEnum() {
        assertThat(AlertTypeEnum.CERTIFICATE_FAILURE.getValue()).isEqualTo("certificate_failure");
        assertThat(AlertTypeEnum.DEPLOYMENT_FAILURE.getDisplayName()).isEqualTo("Deployment Failure");
        for (AlertTypeEnum s : AlertTypeEnum.values()) {
            assertThat(s.getValue()).isNotBlank();
            assertThat(s.getDisplayName()).isNotBlank();
        }
    }




    @Test
    void eventSource() {
        assertThat(EventSource.CERT_MANAGER.value()).isEqualTo("certping-cert-manager");
        assertThat(EventSource.SCHEDULER.value()).isEqualTo("certping-scheduler");
        assertThat(EventSource.AGENT.value()).isEqualTo("certping-agent");
    }

}
