// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.service.FeatureFlagResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureLifecycleLockTest {

    @Mock private JdbcTemplate jdbc;
    @Mock private FeatureFlagResolver resolver;
    @InjectMocks private FeatureLifecycleLock lock;

    @Test
    void theKeyIsStableAndDistinctPerOrganizationAndFeature() {
        long key = FeatureLifecycleLock.lockKey(7L, "INTEGRATIONS");

        assertThat(FeatureLifecycleLock.lockKey(7L, "INTEGRATIONS")).isEqualTo(key);
        assertThat(FeatureLifecycleLock.lockKey(8L, "INTEGRATIONS")).isNotEqualTo(key);
        assertThat(FeatureLifecycleLock.lockKey(7L, "PQC_READINESS")).isNotEqualTo(key);
        // Pinned: a key that changed between releases would let an old and a new pod run side by side.
        assertThat(FeatureLifecycleLock.lockKey(1L, "DISCOVERY")).isEqualTo(424794681373803863L);
    }

    @Test
    void lockTakesATransactionScopedAdvisoryLockOnTheKey() {
        lock.lock(7L, "DISCOVERY");

        verify(jdbc).queryForObject(eq("SELECT pg_advisory_xact_lock(?)::text"), eq(String.class),
                eq(FeatureLifecycleLock.lockKey(7L, "DISCOVERY")));
    }

    @Test
    void severalFeaturesAreLockedInSortedOrderThenReadPastTheCache() {
        when(resolver.resolveUncached(anyString(), eq(7L))).thenReturn(true);

        lock.lockAndAssertEnabled(7L, List.of("LETS_ENCRYPT", "CERTIFICATE_ISSUANCE", "CERTIFICATE_DEPLOYMENT"));

        ArgumentCaptor<Object> keys = ArgumentCaptor.forClass(Object.class);
        verify(jdbc, times(3)).queryForObject(anyString(), eq(String.class), keys.capture());
        assertThat(keys.getAllValues()).containsExactly(
                FeatureLifecycleLock.lockKey(7L, "CERTIFICATE_DEPLOYMENT"),
                FeatureLifecycleLock.lockKey(7L, "CERTIFICATE_ISSUANCE"),
                FeatureLifecycleLock.lockKey(7L, "LETS_ENCRYPT"));
        var order = inOrder(jdbc, resolver);
        order.verify(jdbc, times(3)).queryForObject(anyString(), eq(String.class), keys.capture());
        order.verify(resolver).resolveUncached("LETS_ENCRYPT", 7L);
    }

    @Test
    void aFeatureSwitchedOffWhileWaitingIsRefused() {
        when(resolver.resolveUncached("INTEGRATIONS", 7L)).thenReturn(false);

        assertThatThrownBy(() -> lock.lockAndAssertEnabled(7L, "INTEGRATIONS"))
                .isInstanceOf(FeatureDisabledException.class);
    }
}
