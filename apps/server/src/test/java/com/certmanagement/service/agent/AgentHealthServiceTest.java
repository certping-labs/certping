// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentHealthResponseDto;
import com.certmanagement.entity.AgentHealthStatusEntity;
import com.certmanagement.entity.Organization;
import com.certmanagement.enums.AgentHealthOverallStatus;
import com.certmanagement.exception.UnknownOrganizationForHeartbeatException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.AgentHealthHeartbeat;
import com.certmanagement.repository.AgentHealthStatusRepository;
import com.certmanagement.repository.OrganizationRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentHealthServiceTest {

    private final com.certmanagement.service.audit.MonitoringAuditRecorder monitoringAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class);

    @Mock private OrganizationRepository organizationRepository;
    @Mock private AgentHealthStatusRepository agentHealthStatusRepository;
    @Mock private CertAgentPublisher certAgentPublisher;

    private EmbeddedDatabase embeddedDatabase;
    private PlatformTransactionManager transactionManager;

    @BeforeEach
    void setUpDataSource() {
        embeddedDatabase = new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).build();
        transactionManager = new DataSourceTransactionManager(embeddedDatabase);
    }

    @AfterEach
    void shutdownDataSource() {
        if (embeddedDatabase != null) {
            embeddedDatabase.shutdown();
        }
    }

    private AgentHealthService service() {
        return new AgentHealthService(organizationRepository, agentHealthStatusRepository, certAgentPublisher, transactionManager, monitoringAudit);
    }

    @Test
    void getOrganizationHealthView_staleHeartbeat_marksUnhealthy() {
        Long organizationId = 1L;
        Organization organization = Organization.builder()
                .id(organizationId)
                .name("Acme")
                .domain("acme.example")
                .agentHeartbeatCadenceMinutes(5)
                .build();
        AgentHealthStatusEntity status = AgentHealthStatusEntity.builder()
                .organizationId(organizationId)
                .listening(true)
                .agentCheckedAt(OffsetDateTime.now().minusMinutes(10))
                .cmsReceivedAt(OffsetDateTime.now().minusMinutes(10))
                .build();

        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(agentHealthStatusRepository.findById(organizationId)).thenReturn(Optional.of(status));

        AgentHealthService service = service();
        AgentHealthResponseDto dto = service.getOrganizationHealthView(organizationId);

        assertThat(dto.isStale()).isTrue();
        assertThat(dto.getOverallStatus()).isEqualTo(AgentHealthOverallStatus.UNHEALTHY);
        assertThat(dto.getFailureReason()).contains("Missed 2 heartbeats");
    }

    @Test
    void saveHeartbeat_cadenceMismatch_publishesDbCadenceToAgent() {
        Long organizationId = 3L;
        Organization organization = Organization.builder()
                .id(organizationId)
                .name("Acme")
                .domain("acme.example")
                .agentHeartbeatCadenceMinutes(10)
                .build();
        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(agentHealthStatusRepository.findById(organizationId))
                .thenReturn(Optional.of(AgentHealthStatusEntity.builder().organizationId(organizationId).build()));

        AgentHealthHeartbeat response = new AgentHealthHeartbeat();
        response.setOrganizationId("3");
        response.setListening(true);
        response.setRespondedAt(OffsetDateTime.now().toString());
        response.setHeartbeatCadenceMinutes(7);

        assertThat(service().saveHeartbeat(response)).isTrue();
        // An agent's heartbeat is telemetry, never an audit row: only a member's cadence change is.
        verifyNoInteractions(monitoringAudit);

        assertThat(organization.getAgentHeartbeatCadenceMinutes()).isEqualTo(10);
        verify(organizationRepository, never()).save(organization);
        verify(certAgentPublisher).publishHeartbeatCadenceUpdate(eq("3"), eq("B2B"), eq(10));
    }

    @Test
    void saveHeartbeat_reportedCadenceMatches_doesNotResaveOrg() {
        Long organizationId = 4L;
        Organization organization = Organization.builder()
                .id(organizationId)
                .name("Acme")
                .domain("acme.example")
                .agentHeartbeatCadenceMinutes(5)
                .build();
        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(agentHealthStatusRepository.findById(organizationId))
                .thenReturn(Optional.of(AgentHealthStatusEntity.builder().organizationId(organizationId).build()));

        AgentHealthHeartbeat response = new AgentHealthHeartbeat();
        response.setOrganizationId("4");
        response.setListening(true);
        response.setRespondedAt(OffsetDateTime.now().toString());
        response.setHeartbeatCadenceMinutes(5);

        assertThat(service().saveHeartbeat(response)).isTrue();
        // An agent's heartbeat is telemetry, never an audit row: only a member's cadence change is.
        verifyNoInteractions(monitoringAudit);

        verify(organizationRepository, never()).save(organization);
        verify(certAgentPublisher, never()).publishHeartbeatCadenceUpdate(anyString(), anyString(), anyInt());
    }

    @Test
    void saveHeartbeat_invalidOrganizationId_returnsFalse() {
        AgentHealthHeartbeat response = new AgentHealthHeartbeat();
        response.setOrganizationId("not-a-number");
        assertThat(service().saveHeartbeat(response)).isFalse();
    }

    @Test
    void saveHeartbeat_unknownOrganization_throws() {
        when(organizationRepository.findById(99L)).thenReturn(Optional.empty());
        AgentHealthHeartbeat response = new AgentHealthHeartbeat();
        response.setOrganizationId("99");
        response.setListening(true);
        response.setRespondedAt(OffsetDateTime.now().toString());
        UnknownOrganizationForHeartbeatException ex = assertThrows(
                UnknownOrganizationForHeartbeatException.class, () -> service().saveHeartbeat(response));
        assertThat(ex.getOrganizationId()).isEqualTo(99L);
    }

    @Test
    void saveHeartbeat_retriesOnOptimisticLock() {
        Long organizationId = 5L;
        Organization org = Organization.builder()
                .id(organizationId)
                .name("Acme")
                .domain("acme.example")
                .agentHeartbeatCadenceMinutes(5)
                .build();
        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(org));
        AgentHealthStatusEntity healthRow = AgentHealthStatusEntity.builder()
                .organizationId(organizationId)
                .version(1L)
                .build();
        when(agentHealthStatusRepository.findById(organizationId)).thenReturn(Optional.of(healthRow));
        when(agentHealthStatusRepository.save(any()))
                .thenThrow(new ObjectOptimisticLockingFailureException(AgentHealthStatusEntity.class, organizationId))
                .thenAnswer(invocation -> invocation.getArgument(0));

        AgentHealthHeartbeat response = new AgentHealthHeartbeat();
        response.setOrganizationId("5");
        response.setListening(true);
        response.setRespondedAt(OffsetDateTime.now().toString());

        assertThat(service().saveHeartbeat(response)).isTrue();
        // An agent's heartbeat is telemetry, never an audit row: only a member's cadence change is.
        verifyNoInteractions(monitoringAudit);
        verify(agentHealthStatusRepository, times(2)).save(any(AgentHealthStatusEntity.class));
    }

    @Test
    void isOptimisticLockFailure_recognizesWrappedOptimisticLock() {
        var root = new ObjectOptimisticLockingFailureException(AgentHealthStatusEntity.class, 1L);
        var ex = new org.springframework.transaction.TransactionSystemException("commit failed", root);
        assertThat(AgentHealthService.isOptimisticLockFailure(ex)).isTrue();
    }

    @Test
    void updateHeartbeatCadenceMinutes_outOfRange_throws() {
        Long organizationId = 2L;
        AgentHealthService service = service();

        assertThatThrownBy(() -> service.updateHeartbeatCadenceMinutes(organizationId, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("between 1 and 60");
    }
}
