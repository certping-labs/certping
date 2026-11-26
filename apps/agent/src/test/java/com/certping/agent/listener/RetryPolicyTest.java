// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.config.AgentProperties;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RetryPolicyTest {

    @Test
    void fromProperties_copiesAllFields() {
        RetryPolicy p = RetryPolicy.from(new AgentProperties.RetryProperties());

        assertThat(p.maxScheduledRetries()).isEqualTo(8);
        assertThat(p.hardCapNewOrder()).isEqualTo(Duration.ofHours(48));
        assertThat(p.hardCapRenewal()).isEqualTo(Duration.ofHours(168));
        assertThat(p.jitterPercent()).isEqualTo(10);
        assertThat(p.blindBackoff()).first().isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void hardCapFor_selectsRenewalVsNewOrder() {
        RetryPolicy p = RetryPolicy.from(new AgentProperties.RetryProperties());

        assertThat(p.hardCapFor(false)).isEqualTo(Duration.ofHours(48));
        assertThat(p.hardCapFor(true)).isEqualTo(Duration.ofHours(168));
    }

    @Test
    void blindBackoffFor_clampsToCurveBounds() {
        RetryPolicy p = new RetryPolicy(8, Map.of(), 200, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168), 0,
                List.of(Duration.ofSeconds(30), Duration.ofMinutes(2), Duration.ofMinutes(10)));

        assertThat(p.blindBackoffFor(-1)).isEqualTo(Duration.ofSeconds(30)); // clamps low
        assertThat(p.blindBackoffFor(0)).isEqualTo(Duration.ofSeconds(30));
        assertThat(p.blindBackoffFor(1)).isEqualTo(Duration.ofMinutes(2));
        assertThat(p.blindBackoffFor(2)).isEqualTo(Duration.ofMinutes(10));
        assertThat(p.blindBackoffFor(99)).isEqualTo(Duration.ofMinutes(10)); // clamps high to last
    }

    @Test
    void emptyBackoffFallsBackToThirtySeconds() {
        RetryPolicy p = new RetryPolicy(8, Map.of(), 200, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168), 0, List.of());

        assertThat(p.blindBackoff()).containsExactly(Duration.ofSeconds(30));
    }

    @Test
    void rejectsInvalidKnobs() {
        assertThatThrownBy(() -> new RetryPolicy(0, Map.of(), 200, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168), 10,
                List.of(Duration.ofSeconds(30))))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new RetryPolicy(8, Map.of(), 200, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168), 101,
                List.of(Duration.ofSeconds(30))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void exhausted_reasonWithoutACap_usesTheGlobalCapOnAllRetries() {
        RetryPolicy p = policy(Map.of("DNS_PROPAGATION_PENDING", 3));

        assertThat(p.exhausted("CA_PROVIDER_THROTTLED", 7, 0)).isFalse();
        assertThat(p.exhausted("CA_PROVIDER_THROTTLED", 8, 0)).isTrue();
    }

    @Test
    void exhausted_reasonWithACap_countsOnlyItsOwnRetries() {
        RetryPolicy p = policy(Map.of("DNS_PROPAGATION_PENDING", 3));

        assertThat(p.exhausted("DNS_PROPAGATION_PENDING", 20, 2)).isFalse();
        assertThat(p.exhausted("DNS_PROPAGATION_PENDING", 20, 3)).isTrue();
    }

    @Test
    void exhausted_negativeReasonCap_isBoundedOnlyByTheAbsoluteCap() {
        RetryPolicy p = policy(Map.of("CA_ORDER_PENDING", -1));

        assertThat(p.exhausted("CA_ORDER_PENDING", 199, 199)).isFalse();
        assertThat(p.exhausted("CA_ORDER_PENDING", 200, 120)).isTrue();
    }

    @Test
    void defaults_leaveAPaidCaOrderToItsOwnHorizon() {
        RetryPolicy p = RetryPolicy.from(new AgentProperties.RetryProperties());

        assertThat(p.exhausted("CA_ORDER_PENDING", 96, 96)).isFalse();
        assertThat(p.exhausted("CA_ORDER_PENDING", 200, 200)).isTrue();
    }

    @Test
    void rejectsAnAbsoluteCapBelowTheGlobalCap() {
        assertThatThrownBy(() -> new RetryPolicy(8, Map.of(), 7, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168), 0,
                List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void exhausted_dnsPropagationIsWaitedForThreeMoreTimesByDefault() {
        RetryPolicy p = RetryPolicy.from(new AgentProperties.RetryProperties());

        assertThat(p.exhausted("DNS_PROPAGATION_PENDING", 2, 2)).isFalse();
        assertThat(p.exhausted("DNS_PROPAGATION_PENDING", 3, 3)).isTrue();
    }

    private static RetryPolicy policy(Map<String, Integer> byReason) {
        return new RetryPolicy(8, byReason, 200, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168), 0, List.of());
    }
}
