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
import org.springframework.transaction.PlatformTransactionManager;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Supplementary coverage for {@link AgentHealthService}: read-view branches (null / healthy /
 * not-listening), cadence get/update paths, heartbeat parse edge cases, and the
 * non-optimistic-exception rethrow.
 */
@ExtendWith(MockitoExtension.class)
class AgentHealthServiceMoreTest {

    private final com.certmanagement.service.audit.MonitoringAuditRecorder monitoringAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class);

    @Mock private OrganizationRepository organizationRepository;
    @Mock private AgentHealthStatusRepository agentHealthStatusRepository;
    @Mock private CertAgentPublisher certAgentPublisher;

    private EmbeddedDatabase embeddedDatabase;
    private PlatformTransactionManager transactionManager;

    @BeforeEach
    void setUp() {
        embeddedDatabase = new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).build();
        transactionManager = new DataSourceTransactionManager(embeddedDatabase);
    }

    @AfterEach
    void tearDown() {
        if (embeddedDatabase != null) {
            embeddedDatabase.shutdown();
        }
    }

    private AgentHealthService service() {
        return new AgentHealthService(organizationRepository, agentHealthStatusRepository, certAgentPublisher, transactionManager, monitoringAudit);
    }

    // ----------------------------------------------------------------- //
    //  getOrganizationHealth / view
    // ----------------------------------------------------------------- //

    @Test
    void getOrganizationHealth_returnsEntityOrNull() {
        AgentHealthStatusEntity e = AgentHealthStatusEntity.builder().organizationId(1L).build();
        when(agentHealthStatusRepository.findById(1L)).thenReturn(Optional.of(e));
        assertThat(service().getOrganizationHealth(1L)).isSameAs(e);

        when(agentHealthStatusRepository.findById(2L)).thenReturn(Optional.empty());
        assertThat(service().getOrganizationHealth(2L)).isNull();
    }

    @Test
    void getOrganizationHealthView_noEntity_returnsUnknown() {
        Organization org = Organization.builder().id(1L).agentHeartbeatCadenceMinutes(5).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        when(agentHealthStatusRepository.findById(1L)).thenReturn(Optional.empty());

        AgentHealthResponseDto dto = service().getOrganizationHealthView(1L);

        assertThat(dto.getOverallStatus()).isEqualTo(AgentHealthOverallStatus.UNKNOWN);
        assertThat(dto.isStale()).isTrue();
        assertThat(dto.getFailureReason()).contains("No heartbeat");
    }

    @Test
    void getOrganizationHealthView_freshAndListening_returnsHealthy() {
        Organization org = Organization.builder().id(1L).agentHeartbeatCadenceMinutes(5).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        AgentHealthStatusEntity e = AgentHealthStatusEntity.builder()
                .organizationId(1L)
                .listening(true)
                .agentCheckedAt(OffsetDateTime.now())
                .cmsReceivedAt(OffsetDateTime.now())
                .build();
        when(agentHealthStatusRepository.findById(1L)).thenReturn(Optional.of(e));

        AgentHealthResponseDto dto = service().getOrganizationHealthView(1L);

        assertThat(dto.getOverallStatus()).isEqualTo(AgentHealthOverallStatus.HEALTHY);
        assertThat(dto.isStale()).isFalse();
        assertThat(dto.getFailureReason()).isNull();
    }

    @Test
    void getOrganizationHealthView_freshButNotListening_returnsUnhealthy() {
        Organization org = Organization.builder().id(1L).agentHeartbeatCadenceMinutes(5).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        AgentHealthStatusEntity e = AgentHealthStatusEntity.builder()
                .organizationId(1L)
                .listening(false)
                .cmsReceivedAt(OffsetDateTime.now())
                .build();
        when(agentHealthStatusRepository.findById(1L)).thenReturn(Optional.of(e));

        AgentHealthResponseDto dto = service().getOrganizationHealthView(1L);

        assertThat(dto.getOverallStatus()).isEqualTo(AgentHealthOverallStatus.UNHEALTHY);
        assertThat(dto.getFailureReason()).contains("not listening");
    }

    @Test
    void getOrganizationHealthView_nullCmsReceivedAt_isStale() {
        Organization org = Organization.builder().id(1L).agentHeartbeatCadenceMinutes(5).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));
        AgentHealthStatusEntity e = AgentHealthStatusEntity.builder()
                .organizationId(1L).listening(true).cmsReceivedAt(null).build();
        when(agentHealthStatusRepository.findById(1L)).thenReturn(Optional.of(e));

        AgentHealthResponseDto dto = service().getOrganizationHealthView(1L);

        assertThat(dto.isStale()).isTrue();
    }

    // ----------------------------------------------------------------- //
    //  cadence get / update
    // ----------------------------------------------------------------- //

    @Test
    void getHeartbeatCadenceMinutes_nullValue_returnsDefault() {
        Organization org = Organization.builder().id(1L).agentHeartbeatCadenceMinutes(null).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));

        assertThat(service().getHeartbeatCadenceMinutes(1L)).isEqualTo(5);
    }

    @Test
    void getHeartbeatCadenceMinutes_orgMissing_throws() {
        when(organizationRepository.findById(1L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service().getHeartbeatCadenceMinutes(1L))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void updateHeartbeatCadenceMinutes_savesAndPublishes() {
        Organization org = Organization.builder().id(1L).orgType("B2B").build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));

        int result = service().updateHeartbeatCadenceMinutes(1L, 15);

        assertThat(result).isEqualTo(15);
        assertThat(org.getAgentHeartbeatCadenceMinutes()).isEqualTo(15);
        verify(organizationRepository).save(org);
        verify(certAgentPublisher).publishHeartbeatCadenceUpdate("1", "B2B", 15);
        verify(monitoringAudit).heartbeatCadenceChanged(1L, 5, 15);
    }

    @Test
    void anUnchangedCadenceRecordsNoAuditRow() {
        Organization organization = Organization.builder().id(1L).orgType("B2B")
                .agentHeartbeatCadenceMinutes(20).build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(organization));

        service().updateHeartbeatCadenceMinutes(1L, 20);

        org.mockito.Mockito.verifyNoInteractions(monitoringAudit);
    }

    @Test
    void updateHeartbeatCadenceMinutes_orgMissing_throws() {
        when(organizationRepository.findById(1L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service().updateHeartbeatCadenceMinutes(1L, 10))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void updateHeartbeatCadenceMinutes_tooLow_throws() {
        assertThatThrownBy(() -> service().updateHeartbeatCadenceMinutes(1L, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ----------------------------------------------------------------- //
    //  saveHeartbeat — parse + exception paths
    // ----------------------------------------------------------------- //

    @Test
    void saveHeartbeat_invalidRespondedAt_storesNullCheckedAt() {
        Long orgId = 1L;
        Organization org = Organization.builder().id(orgId).agentHeartbeatCadenceMinutes(5).build();
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org));
        when(agentHealthStatusRepository.findById(orgId))
                .thenReturn(Optional.of(AgentHealthStatusEntity.builder().organizationId(orgId).build()));

        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("1");
        hb.setListening(true);
        hb.setRespondedAt("not-a-timestamp");

        assertThat(service().saveHeartbeat(hb)).isTrue();

        verify(agentHealthStatusRepository).save(argThat(e -> e.getAgentCheckedAt() == null));
    }

    @Test
    void saveHeartbeat_notListening_setsUnhealthyErrorFields() {
        Long orgId = 1L;
        Organization org = Organization.builder().id(orgId).agentHeartbeatCadenceMinutes(5).build();
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org));
        when(agentHealthStatusRepository.findById(orgId))
                .thenReturn(Optional.of(AgentHealthStatusEntity.builder().organizationId(orgId).build()));

        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("1");
        hb.setListening(false);
        hb.setRespondedAt(null);

        service().saveHeartbeat(hb);

        verify(agentHealthStatusRepository).save(argThat(e ->
                e.getOverallStatus() == AgentHealthOverallStatus.UNHEALTHY
                        && "AGENT_NOT_LISTENING".equals(e.getLastErrorCode())));
    }

    @Test
    void saveHeartbeat_nonOptimisticException_rethrows() {
        Long orgId = 1L;
        when(organizationRepository.findById(orgId)).thenReturn(Optional.empty());

        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("1");
        hb.setListening(true);

        assertThatThrownBy(() -> service().saveHeartbeat(hb))
                .isInstanceOf(UnknownOrganizationForHeartbeatException.class);
    }

    @Test
    void saveHeartbeat_reportedCadenceOutOfRange_skipsReconcile() {
        Long orgId = 1L;
        Organization org = Organization.builder()
                .id(orgId).agentHeartbeatCadenceMinutes(5).orgType("B2B").build();
        when(organizationRepository.findById(orgId)).thenReturn(Optional.of(org));
        when(agentHealthStatusRepository.findById(orgId))
                .thenReturn(Optional.of(AgentHealthStatusEntity.builder().organizationId(orgId).build()));

        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("1");
        hb.setListening(true);
        hb.setHeartbeatCadenceMinutes(999); // out of [1,60] -> reconcile no-op

        service().saveHeartbeat(hb);

        verify(certAgentPublisher, never()).publishHeartbeatCadenceUpdate(anyString(), anyString(), anyInt());
    }

    @Test
    void isOptimisticLockFailure_falseForUnrelated() {
        assertThat(AgentHealthService.isOptimisticLockFailure(new RuntimeException("x"))).isFalse();
    }
}
