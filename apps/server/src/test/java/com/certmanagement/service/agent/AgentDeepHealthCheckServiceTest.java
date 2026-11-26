// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentDeepHealthTriggerResponseDto;
import com.certmanagement.entity.AgentDeepHealthCheckChunkEntity;
import com.certmanagement.entity.AgentDeepHealthCheckEntity;
import com.certmanagement.enums.AgentDeepHealthCheckStatus;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.AgentDeepHealthCheckResponse;
import com.certmanagement.messaging.model.AgentDeepHealthMetricResult;
import com.certmanagement.repository.AgentDeepHealthCheckChunkRepository;
import com.certmanagement.repository.AgentDeepHealthCheckMetricRepository;
import com.certmanagement.repository.AgentDeepHealthCheckRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentDeepHealthCheckServiceTest {

    private final com.certmanagement.service.audit.MonitoringAuditRecorder monitoringAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class);

    @Mock private AgentDeepHealthPathDerivationService pathDerivationService;
    @Mock private AgentDeepHealthCheckRepository checkRepository;
    @Mock private AgentDeepHealthCheckChunkRepository chunkRepository;
    @Mock private AgentDeepHealthCheckMetricRepository metricRepository;
    @Mock private CertAgentPublisher certAgentPublisher;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;

    private AgentDeepHealthCheckService service;

    @BeforeEach
    void setUp() {
        service = new AgentDeepHealthCheckService(
                pathDerivationService,
                checkRepository,
                chunkRepository,
                metricRepository,
                certAgentPublisher,
                orgTypeResolver, monitoringAudit);
        lenient().when(orgTypeResolver.resolve(any(Long.class))).thenReturn("B2B");
    }

    @Test
    void trigger_createsCheckAndPublishesCommands() {
        when(pathDerivationService.derivePaths(5L)).thenReturn(List.of(
                "https://kv.vault.azure.net/secrets/a",
                "https://kv.vault.azure.net/secrets/b"));

        AgentDeepHealthTriggerResponseDto response = service.trigger(5L);

        assertThat(response.getDeepCheckId()).startsWith("dhc-");
        assertThat(response.getStatus()).isEqualTo(AgentDeepHealthCheckStatus.PENDING);
        verify(checkRepository).save(any(AgentDeepHealthCheckEntity.class));
        verify(certAgentPublisher).publishDeepHealthCheck(any());
        verify(monitoringAudit).deepCheckRequested(5L, response.getDeepCheckId());
    }

    @Test
    void ingestResponse_isIdempotentByMetricKey() {
        AgentDeepHealthCheckEntity entity = AgentDeepHealthCheckEntity.builder()
                .deepCheckId("dhc-1")
                .requestId("req-1")
                .correlationId("corr-1")
                .organizationId(5L)
                .status(AgentDeepHealthCheckStatus.PENDING)
                .expectedChunks(1)
                .receivedChunks(0)
                .build();
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-1", 5L)).thenReturn(Optional.of(entity));
        when(chunkRepository.existsByDeepCheckIdAndChunkIndex("dhc-1", 0)).thenReturn(false, true);
        when(chunkRepository.countByDeepCheckId("dhc-1")).thenReturn(1L, 1L);
        when(chunkRepository.findByDeepCheckIdOrderByChunkIndexAsc("dhc-1"))
                .thenReturn(List.of(AgentDeepHealthCheckChunkEntity.builder()
                        .deepCheckId("dhc-1")
                        .organizationId(5L)
                        .chunkIndex(0)
                        .status(AgentDeepHealthCheckStatus.SUCCESS)
                        .build()));
        when(metricRepository.existsByDeepCheckIdAndMetricKey("dhc-1", "kv.1")).thenReturn(false, true);

        AgentDeepHealthMetricResult metric = new AgentDeepHealthMetricResult();
        metric.setMetricKey("kv.1");
        metric.setMetricName("Key Vault Path Exists");
        metric.setMetricGroup("key_vault");
        metric.setStatus("PASS");
        metric.setPath("https://kv.vault.azure.net/secrets/a");
        metric.setMessage("ok");

        AgentDeepHealthCheckResponse response = new AgentDeepHealthCheckResponse();
        response.setDeepCheckId("dhc-1");
        response.setOrganizationId("5");
        response.setStatus("SUCCESS");
        response.setChunkIndex(0);
        response.setTotalChunks(1);
        response.setMetrics(List.of(metric));

        service.ingestResponse(response);
        service.ingestResponse(response);
        // The agent's results are the check's own record, never audit rows: only the member's request is.
        org.mockito.Mockito.verifyNoInteractions(monitoringAudit);

        verify(metricRepository, times(1)).save(any());
        verify(chunkRepository, times(1)).save(any(AgentDeepHealthCheckChunkEntity.class));
        ArgumentCaptor<AgentDeepHealthCheckEntity> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckEntity.class);
        verify(checkRepository, atLeastOnce()).save(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(AgentDeepHealthCheckStatus.SUCCESS);
    }

    @Test
    void ingestResponse_outOfOrderChunks_doNotPrematurelyComplete() {
        AgentDeepHealthCheckEntity entity = AgentDeepHealthCheckEntity.builder()
                .deepCheckId("dhc-2")
                .requestId("req-2")
                .correlationId("corr-2")
                .organizationId(5L)
                .status(AgentDeepHealthCheckStatus.PENDING)
                .expectedChunks(3)
                .receivedChunks(0)
                .build();
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-2", 5L)).thenReturn(Optional.of(entity));
        when(chunkRepository.existsByDeepCheckIdAndChunkIndex("dhc-2", 2)).thenReturn(false);
        when(chunkRepository.countByDeepCheckId("dhc-2")).thenReturn(1L);

        AgentDeepHealthCheckResponse response = new AgentDeepHealthCheckResponse();
        response.setDeepCheckId("dhc-2");
        response.setOrganizationId("5");
        response.setStatus("SUCCESS");
        response.setChunkIndex(2);
        response.setTotalChunks(3);
        response.setMetrics(List.of());

        service.ingestResponse(response);

        ArgumentCaptor<AgentDeepHealthCheckEntity> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckEntity.class);
        verify(checkRepository).save(captor.capture());
        assertThat(captor.getValue().getReceivedChunks()).isEqualTo(1);
        assertThat(captor.getValue().getStatus()).isEqualTo(AgentDeepHealthCheckStatus.IN_PROGRESS);
    }

    @Test
    void ingestResponse_aggregateUsesWorstChunkStatus() {
        AgentDeepHealthCheckEntity entity = AgentDeepHealthCheckEntity.builder()
                .deepCheckId("dhc-3")
                .requestId("req-3")
                .correlationId("corr-3")
                .organizationId(5L)
                .status(AgentDeepHealthCheckStatus.PENDING)
                .expectedChunks(2)
                .receivedChunks(1)
                .build();
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-3", 5L)).thenReturn(Optional.of(entity));
        when(chunkRepository.existsByDeepCheckIdAndChunkIndex("dhc-3", 1)).thenReturn(false);
        when(chunkRepository.countByDeepCheckId("dhc-3")).thenReturn(2L);
        when(chunkRepository.findByDeepCheckIdOrderByChunkIndexAsc("dhc-3"))
                .thenReturn(List.of(
                        AgentDeepHealthCheckChunkEntity.builder()
                                .deepCheckId("dhc-3")
                                .organizationId(5L)
                                .chunkIndex(0)
                                .status(AgentDeepHealthCheckStatus.PARTIAL)
                                .build(),
                        AgentDeepHealthCheckChunkEntity.builder()
                                .deepCheckId("dhc-3")
                                .organizationId(5L)
                                .chunkIndex(1)
                                .status(AgentDeepHealthCheckStatus.SUCCESS)
                                .build()));

        AgentDeepHealthCheckResponse response = new AgentDeepHealthCheckResponse();
        response.setDeepCheckId("dhc-3");
        response.setOrganizationId("5");
        response.setStatus("SUCCESS");
        response.setChunkIndex(1);
        response.setTotalChunks(2);
        response.setMetrics(List.of());

        service.ingestResponse(response);

        ArgumentCaptor<AgentDeepHealthCheckEntity> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckEntity.class);
        verify(checkRepository).save(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(AgentDeepHealthCheckStatus.PARTIAL);
    }
}
