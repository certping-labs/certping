// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class RenewalTimingTest {

    private static final OffsetDateTime FROM = OffsetDateTime.of(2026, 10, 1, 0, 0, 0, 0, ZoneOffset.UTC);

    @Test
    void yearLongCertificateKeepsTheConfiguredWindow() {
        OffsetDateTime to = FROM.plusDays(365);
        assertThat(RenewalTiming.eligibleAt(FROM, to, 30)).isEqualTo(to.minusDays(30));
    }

    @Test
    void ninetyDayCertificateRenewsAtTwoThirds() {
        OffsetDateTime to = FROM.plusDays(90);
        assertThat(RenewalTiming.eligibleAt(FROM, to, 30)).isEqualTo(to.minusDays(30));
        assertThat(RenewalTiming.eligibleAt(FROM, to, 45)).as("a wider window is capped").isEqualTo(to.minusDays(30));
    }

    @Test
    void shortLivedCertificatesAreCappedAtAThirdOfTheirLifetime() {
        assertThat(RenewalTiming.eligibleAt(FROM, FROM.plusDays(64), 30)).isEqualTo(FROM.plusDays(64).minusDays(21));
        assertThat(RenewalTiming.eligibleAt(FROM, FROM.plusDays(10), 30)).isEqualTo(FROM.plusDays(10).minusDays(3));
        assertThat(RenewalTiming.eligibleAt(FROM, FROM.plusDays(2), 30)).as("never less than a day").isEqualTo(FROM.plusDays(1));
    }

    @Test
    void unknownStartOrBadWindowFallsBackToTheWindow() {
        OffsetDateTime to = FROM.plusDays(64);
        assertThat(RenewalTiming.eligibleAt(null, to, 30)).isEqualTo(to.minusDays(30));
        assertThat(RenewalTiming.eligibleAt(FROM, to, null)).isEqualTo(to.minusDays(21));
        assertThat(RenewalTiming.eligibleAt(FROM, to, 0)).isEqualTo(to.minusDays(21));
        assertThat(RenewalTiming.eligibleAt(to, FROM, 30)).as("inverted validity").isEqualTo(FROM.minusDays(30));
    }
}
