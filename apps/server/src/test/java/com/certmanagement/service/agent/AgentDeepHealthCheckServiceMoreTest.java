// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentDeepHealthCheckDto;
import com.certmanagement.dto.agent.AgentDeepHealthMetricDto;
import com.certmanagement.entity.AgentDeepHealthCheckChunkEntity;
import com.certmanagement.entity.AgentDeepHealthCheckEntity;
import com.certmanagement.entity.AgentDeepHealthCheckMetricEntity;
import com.certmanagement.enums.AgentDeepHealthCheckStatus;
import com.certmanagement.enums.AgentDeepHealthMetricStatus;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.AgentDeepHealthCheckResponse;
import com.certmanagement.messaging.model.AgentDeepHealthMetricResult;
import com.certmanagement.repository.AgentDeepHealthCheckChunkRepository;
import com.certmanagement.repository.AgentDeepHealthCheckMetricRepository;
import com.certmanagement.repository.AgentDeepHealthCheckRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Supplementary coverage for {@link AgentDeepHealthCheckService}: list / get / getMetrics,
 * timeout transition in applyTimeoutAndMap, ingestResponse early-return guards, FAILED
 * aggregation, and metric/check-status parse fallbacks.
 */
@ExtendWith(MockitoExtension.class)
class AgentDeepHealthCheckServiceMoreTest {

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
                pathDerivationService, checkRepository, chunkRepository,
                metricRepository, certAgentPublisher, orgTypeResolver, mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class));
    }

    private AgentDeepHealthCheckEntity check(AgentDeepHealthCheckStatus status, OffsetDateTime requestedAt) {
        return AgentDeepHealthCheckEntity.builder()
                .deepCheckId("dhc-1")
                .organizationId(5L)
                .status(status)
                .expectedChunks(1)
                .receivedChunks(0)
                .requestedAt(requestedAt)
                .build();
    }

    // ----------------------------------------------------------------- //
    //  trigger — no paths -> single empty chunk
    // ----------------------------------------------------------------- //

    @Test
    void trigger_noPaths_publishesSingleEmptyChunk() {
        when(pathDerivationService.derivePaths(5L)).thenReturn(List.of());
        when(orgTypeResolver.resolve(5L)).thenReturn("B2B");

        service.trigger(5L);

        verify(certAgentPublisher, times(1)).publishDeepHealthCheck(any());
    }

    // ----------------------------------------------------------------- //
    //  list / get / getMetrics
    // ----------------------------------------------------------------- //

    @Test
    void list_mapsEntitiesToDtos() {
        AgentDeepHealthCheckEntity e = check(AgentDeepHealthCheckStatus.SUCCESS, OffsetDateTime.now());
        Page<AgentDeepHealthCheckEntity> page = new PageImpl<>(List.of(e));
        when(checkRepository.findByOrganizationIdOrderByRequestedAtDesc(eq(5L), any()))
                .thenReturn(page);

        Page<AgentDeepHealthCheckDto> result = service.list(5L, PageRequest.of(0, 10));

        assertThat(result.getContent()).hasSize(1);
        assertThat(result.getContent().get(0).getDeepCheckId()).isEqualTo("dhc-1");
    }

    @Test
    void get_found_returnsDto() {
        AgentDeepHealthCheckEntity e = check(AgentDeepHealthCheckStatus.SUCCESS, OffsetDateTime.now());
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-1", 5L)).thenReturn(Optional.of(e));

        AgentDeepHealthCheckDto dto = service.get(5L, "dhc-1");

        assertThat(dto.getStatus()).isEqualTo(AgentDeepHealthCheckStatus.SUCCESS);
    }

    @Test
    void get_notFound_throws() {
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-x", 5L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.get(5L, "dhc-x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void getMetrics_mapsMetricEntities() {
        AgentDeepHealthCheckMetricEntity m = AgentDeepHealthCheckMetricEntity.builder()
                .deepCheckId("dhc-1").organizationId(5L)
                .metricKey("kv.1").metricName("name").metricGroup("group")
                .status(AgentDeepHealthMetricStatus.PASS)
                .path("p").message("ok").build();
        when(metricRepository.findByDeepCheckIdAndOrganizationIdOrderByIdAsc("dhc-1", 5L))
                .thenReturn(List.of(m));

        List<AgentDeepHealthMetricDto> dtos = service.getMetrics(5L, "dhc-1");

        assertThat(dtos).hasSize(1);
        assertThat(dtos.get(0).getMetricKey()).isEqualTo("kv.1");
        assertThat(dtos.get(0).getStatus()).isEqualTo(AgentDeepHealthMetricStatus.PASS);
    }

    // ----------------------------------------------------------------- //
    //  applyTimeoutAndMap — timeout transition
    // ----------------------------------------------------------------- //

    @Test
    void get_pendingPastTimeout_marksTimedOut() {
        AgentDeepHealthCheckEntity e = check(
                AgentDeepHealthCheckStatus.PENDING,
                OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(10));
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-1", 5L)).thenReturn(Optional.of(e));

        AgentDeepHealthCheckDto dto = service.get(5L, "dhc-1");

        assertThat(dto.getStatus()).isEqualTo(AgentDeepHealthCheckStatus.TIMED_OUT);
        assertThat(e.getCompletedAt()).isNotNull();
        verify(checkRepository).save(e);
    }

    // ----------------------------------------------------------------- //
    //  ingestResponse — guards
    // ----------------------------------------------------------------- //

    @Test
    void ingestResponse_missingIdentifiers_ignored() {
        AgentDeepHealthCheckResponse r = new AgentDeepHealthCheckResponse();
        r.setDeepCheckId(null);
        r.setOrganizationId(null);

        service.ingestResponse(r);

        verifyNoInteractions(checkRepository);
    }

    @Test
    void ingestResponse_invalidOrganizationId_ignored() {
        AgentDeepHealthCheckResponse r = new AgentDeepHealthCheckResponse();
        r.setDeepCheckId("dhc-1");
        r.setOrganizationId("not-a-number");

        service.ingestResponse(r);

        verifyNoInteractions(checkRepository);
    }

    @Test
    void ingestResponse_checkNotFound_ignored() {
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-1", 5L)).thenReturn(Optional.empty());
        AgentDeepHealthCheckResponse r = new AgentDeepHealthCheckResponse();
        r.setDeepCheckId("dhc-1");
        r.setOrganizationId("5");

        service.ingestResponse(r);

        verify(chunkRepository, never()).save(any());
    }

    @Test
    void ingestResponse_failedChunk_aggregatesFailedAndStoresError() {
        AgentDeepHealthCheckEntity e = check(AgentDeepHealthCheckStatus.PENDING, OffsetDateTime.now());
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-1", 5L)).thenReturn(Optional.of(e));
        when(chunkRepository.existsByDeepCheckIdAndChunkIndex("dhc-1", 0)).thenReturn(false);
        when(chunkRepository.countByDeepCheckId("dhc-1")).thenReturn(1L);
        when(chunkRepository.findByDeepCheckIdOrderByChunkIndexAsc("dhc-1"))
                .thenReturn(List.of(AgentDeepHealthCheckChunkEntity.builder()
                        .deepCheckId("dhc-1").chunkIndex(0)
                        .status(AgentDeepHealthCheckStatus.FAILED).build()));

        AgentDeepHealthCheckResponse r = new AgentDeepHealthCheckResponse();
        r.setDeepCheckId("dhc-1");
        r.setOrganizationId("5");
        r.setStatus("FAILED");
        r.setChunkIndex(0);
        r.setErrorCode("KV_UNREACHABLE");
        r.setErrorMessage("vault down");

        service.ingestResponse(r);

        assertThat(e.getStatus()).isEqualTo(AgentDeepHealthCheckStatus.FAILED);
        assertThat(e.getErrorCode()).isEqualTo("KV_UNREACHABLE");
        assertThat(e.getCompletedAt()).isNotNull();
    }

    @Test
    void ingestResponse_metricWithBlankKey_skipped() {
        AgentDeepHealthCheckEntity e = check(AgentDeepHealthCheckStatus.PENDING, OffsetDateTime.now());
        e.setExpectedChunks(2); // don't complete -> no aggregate
        when(checkRepository.findByDeepCheckIdAndOrganizationId("dhc-1", 5L)).thenReturn(Optional.of(e));
        when(chunkRepository.existsByDeepCheckIdAndChunkIndex("dhc-1", 0)).thenReturn(false);
        when(chunkRepository.countByDeepCheckId("dhc-1")).thenReturn(1L);

        AgentDeepHealthMetricResult blank = new AgentDeepHealthMetricResult();
        blank.setMetricKey("  ");
        AgentDeepHealthMetricResult weird = new AgentDeepHealthMetricResult();
        weird.setMetricKey("kv.weird");
        weird.setStatus("NONSENSE"); // parse fallback -> ERROR

        when(metricRepository.existsByDeepCheckIdAndMetricKey("dhc-1", "kv.weird")).thenReturn(false);

        AgentDeepHealthCheckResponse r = new AgentDeepHealthCheckResponse();
        r.setDeepCheckId("dhc-1");
        r.setOrganizationId("5");
        r.setStatus("IN_PROGRESS"); // normalizeChunkStatus -> SUCCESS
        r.setChunkIndex(0);
        r.setMetrics(List.of(blank, weird));

        service.ingestResponse(r);

        // only the non-blank metric is saved
        verify(metricRepository, times(1)).save(any());
    }
}
