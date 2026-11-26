// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.profile.CertificateProfileConfiguration;
import com.certmanagement.iot.profile.CertificateProfileJsonCodec;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IntuneRenewalEligibilityPolicyTest {

    private static final OffsetDateTime ISSUED_AT = OffsetDateTime.parse("2026-01-01T00:00:00Z");
    private final IntuneRenewalEligibilityPolicy policy = new IntuneRenewalEligibilityPolicy(
            new CertificateProfileJsonCodec(JsonMapper.builderWithJackson2Defaults().build()));

    @Test
    void becomesEligibleAtTheConfiguredPercentageOfActualLifetime() {
        IotDeviceCertificate certificate = certificate(90);
        OffsetDateTime dueAt = certificate.getValidTo().minusDays(18);

        IntuneRenewalEligibilityPolicy.Assessment before = policy.assess(
                List.of(certificate), Map.of(10L, configuration("20")), dueAt.minusSeconds(1));
        IntuneRenewalEligibilityPolicy.Assessment atThreshold = policy.assess(
                List.of(certificate), Map.of(10L, configuration("20")), dueAt);

        assertThat(before.hasThreshold()).isTrue();
        assertThat(before.eligible()).isEmpty();
        assertThat(before.earliestDueAt()).isEqualTo(dueAt);
        assertThat(atThreshold.eligible()).hasSize(1);
        assertThat(atThreshold.eligible().getFirst().eligibility().thresholdPercentage()).isEqualTo(20);
    }

    @Test
    void usesTwoYearCertificateLifetimeInsteadOfAThirtyDayFallback() {
        IotDeviceCertificate certificate = certificate(730);
        OffsetDateTime dueAt = certificate.getValidTo().minusDays(146);

        IntuneRenewalEligibilityPolicy.Assessment assessment = policy.assess(
                List.of(certificate), Map.of(10L, configuration(20)), dueAt);

        assertThat(assessment.eligible()).hasSize(1);
        assertThat(assessment.earliestDueAt()).isEqualTo(dueAt);
    }

    @Test
    void missingOrInvalidThresholdNeverFallsBackToThirtyDays() {
        IotDeviceCertificate certificate = certificate(90);

        assertThat(policy.assess(List.of(certificate), Map.of(), certificate.getValidTo().minusDays(1))
                .hasThreshold()).isFalse();
        assertThat(policy.assess(List.of(certificate), Map.of(10L, configuration(100)),
                certificate.getValidTo().minusDays(1)).hasThreshold()).isFalse();
        assertThat(policy.assess(List.of(certificate), Map.of(10L, configuration(20.5)),
                certificate.getValidTo().minusDays(1)).hasThreshold()).isFalse();
    }

    private static IotDeviceCertificate certificate(int lifetimeDays) {
        return IotDeviceCertificate.builder()
                .id(1L).certificateXref("crt-1").profileId(10L)
                .validFrom(ISSUED_AT).validTo(ISSUED_AT.plusDays(lifetimeDays))
                .build();
    }

    private static CertificateProfileConfiguration configuration(Object threshold) {
        return CertificateProfileConfiguration.builder()
                .profileId(10L)
                .providerConfigJson("{\"renewalThresholdPercentage\":"
                        + (threshold instanceof String ? "\"" + threshold + "\"" : threshold)
                        + "}")
                .build();
    }
}
