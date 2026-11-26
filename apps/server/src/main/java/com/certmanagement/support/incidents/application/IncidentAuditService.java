// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.application;

import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.support.incidents.domain.Incident;
import com.certmanagement.support.incidents.domain.IncidentCreationSource;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import org.springframework.stereotype.Service;

/**
 * Records an incident raised in PagerDuty or ServiceNow, in the transaction that stored it, as one
 * {@code audit_events} row ({@code incident.triggered}, {@link SupportAuditRecorder}). An incident CertPing
 * raised on its own is CertPing's row.
 *
 * <p>A member's refused incident is recorded by the endpoint ({@code @AuditFailure} on {@code IncidentController});
 * one CertPing could not raise on its own is recorded here, as CertPing's failure row. Either way the reason comes
 * from the failure's type and status only.
 */
@Service
class IncidentAuditService {

    private final SupportAuditRecorder supportAudit;

    IncidentAuditService(SupportAuditRecorder supportAudit) {
        this.supportAudit = supportAudit;
    }

    /** {@code incident} was raised; call it in the transaction that stored it. */
    void recordSuccess(Incident incident) {
        supportAudit.incidentTriggered(incident);
    }

    /** Raising an incident failed: recorded here when CertPing raised it on its own. */
    void recordFailure(
            Long organizationId,
            IncidentCreationSource source,
            IntegrationProvider provider,
            Exception exception) {
        supportAudit.incidentFailed(organizationId, source, provider, exception);
    }
}
