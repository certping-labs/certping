// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Through the real Spring proxy and JpaTransactionManager: the deletion check runs with no
 * transaction and nothing bound to the thread, so the domain service call holds no pooled
 * connection; the delete itself runs in one.
 */
@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@Import(OrganizationService.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class OrganizationServiceTransactionTest {

    @Autowired private OrganizationService organizationService;
    @MockitoBean private OrganizationRepository organizationRepository;
    @MockitoBean private com.certmanagement.service.audit.OrganizationAuditRecorder organizationAudit;

    private record ThreadState(boolean transactionActive, boolean resourcesBound) {
        static ThreadState now() {
            return new ThreadState(TransactionSynchronizationManager.isActualTransactionActive(),
                    !TransactionSynchronizationManager.getResourceMap().isEmpty());
        }
    }

    @Test
    void theDeleteRunsInsideATransaction() {
        AtomicReference<ThreadState> duringDelete = new AtomicReference<>();
        // The delete's first step; an unknown organization ends it there with a 404.
        when(organizationRepository.findByIdForUpdate(5L)).thenAnswer(inv -> {
            duringDelete.set(ThreadState.now());
            return Optional.empty();
        });

        assertThatThrownBy(() -> organizationService.deleteOrganization(5L)).isInstanceOf(ResourceNotFoundException.class);

        assertThat(duringDelete.get().transactionActive()).isTrue();
    }
}
