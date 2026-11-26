// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationAuditAction;
import org.springframework.stereotype.Service;

/**
 * Records an integration added, changed or removed, in the change's own transaction, as one
 * {@code audit_events} row ({@code integration.*}, {@link SupportAuditRecorder}).
 *
 * <p>A refused change is recorded by the endpoint ({@code @AuditFailure} on {@code IntegrationController}), from
 * the failure's type and status only.
 */
@Service
class IntegrationAuditService {

    private final SupportAuditRecorder supportAudit;

    IntegrationAuditService(SupportAuditRecorder supportAudit) {
        this.supportAudit = supportAudit;
    }

    /**
     * {@code integration} was changed; call it in the change's transaction, after the change was flushed. The
     * row requires that transaction ({@code AuditRecorder.record} is MANDATORY).
     */
    void recordSuccess(Integration integration, IntegrationAuditAction action) {
        supportAudit.integrationChanged(action, integration);
    }
}
