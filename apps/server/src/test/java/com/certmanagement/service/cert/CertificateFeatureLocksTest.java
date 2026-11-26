// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CertificateFeatureLocksTest {

    private static final long ORG = 7L;

    private final FeatureLifecycleLock lock = mock(FeatureLifecycleLock.class);
    private final FeatureFlagResolver resolver = mock(FeatureFlagResolver.class);
    private final CertificateFeatureLocks locks = new CertificateFeatureLocks(lock, resolver);

    @Test
    void locksEverythingInSortedOrderBeforeReadingAnyFlag() {
        when(resolver.resolveUncached(anyString(), eq(ORG))).thenReturn(true);

        locks.lockAndRequire(ORG, List.of("LETS_ENCRYPT", "CERTIFICATE_ISSUANCE", "CERTIFICATE_DEPLOYMENT"),
                List.of("CERTIFICATE_RENEWAL"), "off");

        InOrder order = inOrder(lock, resolver);
        order.verify(lock).lock(ORG, "CERTIFICATE_DEPLOYMENT");
        order.verify(lock).lock(ORG, "CERTIFICATE_ISSUANCE");
        order.verify(lock).lock(ORG, "CERTIFICATE_RENEWAL");
        order.verify(lock).lock(ORG, "LETS_ENCRYPT");
        order.verify(resolver, org.mockito.Mockito.times(3)).resolveUncached(anyString(), eq(ORG));
        verify(resolver, never()).resolveUncached("CERTIFICATE_RENEWAL", ORG);
    }

    @Test
    void aLockedOnlyFeatureMayBeOff() {
        when(resolver.resolveUncached("CERTIFICATE_ISSUANCE", ORG)).thenReturn(true);
        when(resolver.resolveUncached("CERTIFICATE_RENEWAL", ORG)).thenReturn(false);

        locks.lockAndRequire(ORG, List.of("CERTIFICATE_ISSUANCE"), List.of("CERTIFICATE_RENEWAL"), "off");

        verify(lock).lock(ORG, "CERTIFICATE_RENEWAL");
    }

    @Test
    void deploymentOff_isA423WithTheCallersMessage() {
        when(resolver.resolveUncached(anyString(), anyLong())).thenReturn(true);
        when(resolver.resolveUncached("CERTIFICATE_DEPLOYMENT", ORG)).thenReturn(false);

        assertThatThrownBy(() -> locks.lockAndRequire(ORG, List.of("CERTIFICATE_ISSUANCE", "CERTIFICATE_DEPLOYMENT"),
                List.of(), CertPersistenceService.DEPLOYMENT_OFF_MESSAGE))
                .isInstanceOfSatisfying(FeatureDisabledException.class, e -> {
                    assertThat(e.getFeatureKey()).isEqualTo("CERTIFICATE_DEPLOYMENT");
                    assertThat(e.getMessage()).isEqualTo("Automatic deployment is turned off for your organization. "
                            + "Issue the certificate without deployment targets, or ask an admin to turn deployment "
                            + "back on.");
                });
    }

    @Test
    void anotherRequiredFeatureOff_isTheGeneric423() {
        when(resolver.resolveUncached("CERTIFICATE_ISSUANCE", ORG)).thenReturn(false);

        assertThatThrownBy(() -> locks.lockAndRequire(ORG, List.of("CERTIFICATE_ISSUANCE"), List.of(), "off"))
                .isInstanceOfSatisfying(FeatureDisabledException.class,
                        e -> assertThat(e.getFeatureKey()).isEqualTo("CERTIFICATE_ISSUANCE"));
    }
}
