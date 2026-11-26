// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class AutoRenewFeatureLocksTest {

    private final FeatureLifecycleLock lock = mock(FeatureLifecycleLock.class);
    private final AutoRenewFeatureLocks locks = new AutoRenewFeatureLocks(lock);

    @Test
    void featureKeys_areRenewalAndTheCa_sorted_orEveryCaWhenTheResponseNamesNone() {
        assertThat(AutoRenewFeatureLocks.featureKeysFor(CaProvider.GLOBALSIGN))
                .containsExactly("CERTIFICATE_RENEWAL", "GLOBALSIGN");
        assertThat(AutoRenewFeatureLocks.featureKeysFor(null))
                .containsExactly("CERTIFICATE_RENEWAL", "DIGICERT", "GLOBALSIGN", "LETS_ENCRYPT");
    }

    @Test
    void aLockAlreadyHeldIsNotTakenAgain_andTheCertificatesOwnLocksAreEnsured() {
        locks.acquire(1L, List.of("LETS_ENCRYPT", "CERTIFICATE_RENEWAL"));
        locks.ensureHeld(1L, CaProvider.LETS_ENCRYPT);
        locks.ensureHeld(1L, CaProvider.DIGICERT);

        InOrder order = inOrder(lock);
        order.verify(lock).lock(1L, "CERTIFICATE_RENEWAL");
        order.verify(lock).lock(1L, "LETS_ENCRYPT");
        order.verify(lock).lock(1L, "DIGICERT");
        verify(lock, times(3)).lock(anyLong(), anyString());
    }
}
