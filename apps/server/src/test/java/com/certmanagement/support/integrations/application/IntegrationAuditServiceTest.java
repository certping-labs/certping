// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import static org.mockito.Mockito.verify;

import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationAuditAction;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import java.util.Map;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** An integration change is its one audit_events row, written by {@link SupportAuditRecorder}. */
@ExtendWith(MockitoExtension.class)
class IntegrationAuditServiceTest {

    @Mock
    private SupportAuditRecorder supportAudit;

    @ParameterizedTest
    @EnumSource(IntegrationAuditAction.class)
    void eachChangeIsHandedToTheRecorder(IntegrationAuditAction action) {
        Integration integration = new Integration(5L, IntegrationProvider.SLACK, Map.of(), Map.of(), 9L);

        new IntegrationAuditService(supportAudit).recordSuccess(integration, action);

        verify(supportAudit).integrationChanged(action, integration);
    }
}
