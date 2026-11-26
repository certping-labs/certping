// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.application;

import static org.mockito.Mockito.verify;

import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.incidents.domain.Incident;
import com.certmanagement.support.incidents.domain.IncidentCreationSource;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * An incident is its one audit_events row; a failure is recorded here only when CertPing raised the incident on
 * its own.
 */
@ExtendWith(MockitoExtension.class)
class IncidentAuditServiceTest {

    @Mock
    private SupportAuditRecorder supportAudit;

    private IncidentAuditService service;

    @BeforeEach
    void setUp() {
        service = new IncidentAuditService(supportAudit);
    }

    private Incident incident() {
        Incident i = new Incident(5L, 9L, IncidentCreationSource.PUBLIC_API,
                IntegrationProvider.PAGERDUTY, 12345L, "summary", "ext-id", "INC-1", "https://url");
        ReflectionTestUtils.setField(i, "id", 33L);
        return i;
    }

    @Test
    void aTriggerIsHandedToTheRecorder() {
        Incident incident = incident();

        service.recordSuccess(incident);

        verify(supportAudit).incidentTriggered(incident);
    }

    @Test
    void aFailureGoesToTheRecorder() {
        ApiException timeout = new ApiException(504, "SERVICENOW_REQUEST_TIMEOUT", "timeout");

        service.recordFailure(5L, IncidentCreationSource.INTERNAL_API, IntegrationProvider.SERVICENOW_ITSM, timeout);

        verify(supportAudit).incidentFailed(5L, IncidentCreationSource.INTERNAL_API,
                IntegrationProvider.SERVICENOW_ITSM, timeout);
    }
}
