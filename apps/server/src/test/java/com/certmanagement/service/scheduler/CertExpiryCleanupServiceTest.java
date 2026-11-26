// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.testing.Transactions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertExpiryCleanupServiceTest {

    private static final Long   ORG_ID = 7L;
    private static final String XREF   = "cert-cleanup-abc";

    @Mock private CertificateRepository certificateRepository;
    @Mock private CertIssuanceService   certIssuanceService;

    private CertExpiryCleanupService service;
    private CertificateEntity cert;

    @BeforeEach
    void setUp() {
        // Gating (env switch + EXPIRED_CERT_SOFT_DELETE) and the drain loop live in JobPolicy /
        // DrainRunner now; SchedulerJobsTest and DrainRunnerTest cover them.
        service = new CertExpiryCleanupService(certificateRepository, certIssuanceService, Transactions.inline());

        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(1L).organizationId(ORG_ID).domain("example.com").build();
        cert = CertificateEntity.builder()
                .certificateXref(XREF).userDomainCert(udc).status("EXPIRED").build();
    }

    @Test
    void tryProcessOneEligible_emptyQueue_returnsFalse() {
        when(certificateRepository.claimOneExpiredOrRevokedForCleanup(any()))
                .thenReturn(Optional.empty());

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isFalse();
        verify(certIssuanceService, never()).deleteRevoked(any(), any());
    }

    @Test
    void tryProcessOneEligible_claimedCert_callsDeleteRevoked() {
        when(certificateRepository.claimOneExpiredOrRevokedForCleanup(any()))
                .thenReturn(Optional.of(cert));

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        verify(certIssuanceService).deleteRevoked(ORG_ID, XREF);
    }

    @Test
    void tryProcessOneEligible_deleteRevokedThrows_rethrowsForRollback() {
        when(certificateRepository.claimOneExpiredOrRevokedForCleanup(any()))
                .thenReturn(Optional.of(cert));
        doThrow(new RuntimeException("agent unreachable"))
                .when(certIssuanceService).deleteRevoked(any(), any());

        assertThatThrownBy(() -> service.tryProcessOneEligible())
                .isInstanceOf(RuntimeException.class)
                .hasMessage("agent unreachable");
    }
}
