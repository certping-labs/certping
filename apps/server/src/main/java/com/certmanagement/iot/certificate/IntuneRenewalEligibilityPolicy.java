// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.profile.CertificateProfileConfiguration;
import com.certmanagement.iot.profile.CertificateProfileJsonCodec;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Applies Intune's percentage-of-actual-certificate-lifetime renewal rule. */
@Component
@RequiredArgsConstructor
class IntuneRenewalEligibilityPolicy {

    private final CertificateProfileJsonCodec profileJsonCodec;

    Assessment assess(
            List<IotDeviceCertificate> certificates,
            Map<Long, CertificateProfileConfiguration> configurations,
            OffsetDateTime now) {
        List<EligibleCertificate> eligible = new ArrayList<>();
        OffsetDateTime earliestDueAt = null;
        boolean hasThreshold = false;
        for (IotDeviceCertificate certificate : certificates) {
            Optional<Eligibility> eligibility = evaluate(
                    certificate, configurations.get(certificate.getProfileId()), now);
            if (eligibility.isEmpty()) {
                continue;
            }
            hasThreshold = true;
            Eligibility value = eligibility.get();
            earliestDueAt = earliestDueAt == null || value.renewalDueAt().isBefore(earliestDueAt)
                    ? value.renewalDueAt() : earliestDueAt;
            if (value.eligible()) {
                eligible.add(new EligibleCertificate(certificate, value));
            }
        }
        return new Assessment(List.copyOf(eligible), hasThreshold, earliestDueAt);
    }

    private Optional<Eligibility> evaluate(
            IotDeviceCertificate certificate,
            CertificateProfileConfiguration configuration,
            OffsetDateTime now) {
        Integer threshold = renewalThreshold(configuration);
        if (threshold == null || certificate.getValidFrom() == null
                || certificate.getValidTo() == null
                || !certificate.getValidTo().isAfter(certificate.getValidFrom())) {
            return Optional.empty();
        }
        Duration lifetime = Duration.between(certificate.getValidFrom(), certificate.getValidTo());
        OffsetDateTime renewalDueAt = certificate.getValidTo()
                .minus(lifetime.multipliedBy(threshold).dividedBy(100));
        return Optional.of(new Eligibility(
                !now.isBefore(renewalDueAt) && now.isBefore(certificate.getValidTo()),
                renewalDueAt, threshold));
    }

    private Integer renewalThreshold(CertificateProfileConfiguration configuration) {
        if (configuration == null) {
            return null;
        }
        Object raw = profileJsonCodec.readObject(
                configuration.getProviderConfigJson()).get("renewalThresholdPercentage");
        Integer threshold = integer(raw);
        return threshold != null && threshold >= 1 && threshold <= 99 ? threshold : null;
    }

    private static Integer integer(Object value) {
        if (value instanceof Integer number) {
            return number;
        }
        if (value instanceof Number number) {
            double decimal = number.doubleValue();
            return decimal == Math.rint(decimal) ? number.intValue() : null;
        }
        if (value instanceof String text) {
            try {
                return Integer.valueOf(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    record Assessment(
            List<EligibleCertificate> eligible,
            boolean hasThreshold,
            OffsetDateTime earliestDueAt) {}

    record Eligibility(
            boolean eligible,
            OffsetDateTime renewalDueAt,
            int thresholdPercentage) {}

    record EligibleCertificate(
            IotDeviceCertificate certificate,
            Eligibility eligibility) {}
}
