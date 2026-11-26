// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentDeepHealthCheckDto;
import com.certmanagement.dto.agent.AgentDeepHealthMetricDto;
import com.certmanagement.dto.agent.AgentDeepHealthTriggerResponseDto;
import com.certmanagement.entity.AgentDeepHealthCheckChunkEntity;
import com.certmanagement.entity.AgentDeepHealthCheckEntity;
import com.certmanagement.entity.AgentDeepHealthCheckMetricEntity;
import com.certmanagement.enums.AgentDeepHealthCheckStatus;
import com.certmanagement.enums.AgentDeepHealthMetricStatus;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.AgentDeepHealthCheckCommand;
import com.certmanagement.messaging.model.AgentDeepHealthCheckResponse;
import com.certmanagement.messaging.model.AgentDeepHealthMetricResult;
import com.certmanagement.repository.AgentDeepHealthCheckChunkRepository;
import com.certmanagement.repository.AgentDeepHealthCheckMetricRepository;
import com.certmanagement.repository.AgentDeepHealthCheckRepository;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.MonitoringAuditRecorder;
import com.certmanagement.util.MdcIds;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AgentDeepHealthCheckService {

    private static final int MAX_PATHS_PER_MESSAGE = 200;
    private static final long CHECK_TIMEOUT_MINUTES = 5L;

    private final AgentDeepHealthPathDerivationService pathDerivationService;
    private final AgentDeepHealthCheckRepository checkRepository;
    private final AgentDeepHealthCheckChunkRepository chunkRepository;
    private final AgentDeepHealthCheckMetricRepository metricRepository;
    private final CertAgentPublisher certAgentPublisher;
    private final OrgTypeResolver orgTypeResolver;
    /** The deep-check row of the audit trail, written in the check's transaction. */
    private final MonitoringAuditRecorder monitoringAudit;

    @Transactional
    public AgentDeepHealthTriggerResponseDto trigger(Long organizationId) {
        String deepCheckId = "dhc-" + UUID.randomUUID();
        String requestId = MdcIds.requestId();
        // correlationId from frontend via MDC (set by RequestContextInterceptor). Null for any
        // non-HTTP caller — that's fine, the command's correlationId stays empty.
        String mdcCorr = MDC.get("correlationId");
        String correlationId = (mdcCorr == null || mdcCorr.isEmpty() || "unknown".equals(mdcCorr))
                ? null : mdcCorr;
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

        List<String> paths = pathDerivationService.derivePaths(organizationId);
        List<List<String>> chunks = chunk(paths, MAX_PATHS_PER_MESSAGE);
        int totalChunks = Math.max(1, chunks.size());
        String orgType = orgTypeResolver.resolve(organizationId);

        AgentDeepHealthCheckEntity check = AgentDeepHealthCheckEntity.builder()
                .deepCheckId(deepCheckId)
                .requestId(requestId)
                .correlationId(correlationId)
                .organizationId(organizationId)
                .status(AgentDeepHealthCheckStatus.PENDING)
                .expectedChunks(totalChunks)
                .receivedChunks(0)
                .requestedAt(now)
                .build();
        checkRepository.save(check);
        monitoringAudit.deepCheckRequested(organizationId, deepCheckId);

        for (int i = 0; i < totalChunks; i++) {
            List<String> payloadPaths = chunks.isEmpty() ? List.of() : chunks.get(i);
            AgentDeepHealthCheckCommand command = AgentDeepHealthCheckCommand.builder()
                    .deepCheckId(deepCheckId)
                    .requestId(requestId + "-c" + i)
                    .correlationId(correlationId)
                    .organizationId(organizationId.toString())
                    .orgType(orgType)
                    .chunkIndex(i)
                    .totalChunks(totalChunks)
                    .secretHandles(payloadPaths)
                    .requestedAt(now.toString())
                    .build();
            certAgentPublisher.publishDeepHealthCheck(command);
        }

        return AgentDeepHealthTriggerResponseDto.builder()
                .deepCheckId(deepCheckId)
                .status(AgentDeepHealthCheckStatus.PENDING)
                .requestedAt(now)
                .build();
    }

    @Transactional
    public Page<AgentDeepHealthCheckDto> list(Long organizationId, Pageable pageable) {
        return checkRepository.findByOrganizationIdOrderByRequestedAtDesc(organizationId, pageable)
                .map(this::applyTimeoutAndMap);
    }

    @Transactional
    public AgentDeepHealthCheckDto get(Long organizationId, String deepCheckId) {
        AgentDeepHealthCheckEntity entity = checkRepository.findByDeepCheckIdAndOrganizationId(deepCheckId, organizationId)
                .orElseThrow(() -> new IllegalArgumentException("Deep health check not found"));
        return applyTimeoutAndMap(entity);
    }

    @Transactional(readOnly = true)
    public List<AgentDeepHealthMetricDto> getMetrics(Long organizationId, String deepCheckId) {
        return metricRepository.findByDeepCheckIdAndOrganizationIdOrderByIdAsc(deepCheckId, organizationId).stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional
    public void ingestResponse(AgentDeepHealthCheckResponse response) {
        if (response.getDeepCheckId() == null || response.getOrganizationId() == null) {
            log.warn("Ignoring AGENT_DEEP_HEALTH_CHECK_RESPONSE with missing identifiers");
            return;
        }
        Long organizationId;
        try {
            organizationId = Long.parseLong(response.getOrganizationId());
        } catch (Exception ex) {
            log.warn("Ignoring deep-check response with invalid organizationId={}", response.getOrganizationId());
            return;
        }

        AgentDeepHealthCheckEntity check = checkRepository.findByDeepCheckIdAndOrganizationId(response.getDeepCheckId(), organizationId)
                .orElse(null);
        if (check == null) {
            log.warn("Deep-check response does not match any existing run: deepCheckId={} organizationId={}",
                    response.getDeepCheckId(), organizationId);
            return;
        }

        if (check.getStartedAt() == null) {
            check.setStartedAt(OffsetDateTime.now(ZoneOffset.UTC));
        }
        check.setStatus(AgentDeepHealthCheckStatus.IN_PROGRESS);
        check.setLastRespondedAt(parseDate(response.getRespondedAt()));
        int chunkIndex = response.getChunkIndex() != null ? response.getChunkIndex() : 0;
        AgentDeepHealthCheckStatus chunkStatus = normalizeChunkStatus(response.getStatus());
        if (!chunkRepository.existsByDeepCheckIdAndChunkIndex(check.getDeepCheckId(), chunkIndex)) {
            chunkRepository.save(AgentDeepHealthCheckChunkEntity.builder()
                    .deepCheckId(check.getDeepCheckId())
                    .organizationId(organizationId)
                    .chunkIndex(chunkIndex)
                    .status(chunkStatus)
                    .respondedAt(parseDate(response.getRespondedAt()))
                    .build());
        }
        check.setReceivedChunks((int) chunkRepository.countByDeepCheckId(check.getDeepCheckId()));

        List<AgentDeepHealthMetricResult> metrics = response.getMetrics() != null ? response.getMetrics() : List.of();
        for (AgentDeepHealthMetricResult metric : metrics) {
            String metricKey = metric.getMetricKey();
            if (metricKey == null || metricKey.isBlank()) {
                continue;
            }
            if (metricRepository.existsByDeepCheckIdAndMetricKey(check.getDeepCheckId(), metricKey)) {
                continue;
            }
            metricRepository.save(AgentDeepHealthCheckMetricEntity.builder()
                    .deepCheckId(check.getDeepCheckId())
                    .organizationId(organizationId)
                    .chunkIndex(response.getChunkIndex() != null ? response.getChunkIndex() : 0)
                    .metricKey(metricKey)
                    .metricName(metric.getMetricName())
                    .metricGroup(metric.getMetricGroup())
                    .status(parseMetricStatus(metric.getStatus()))
                    .path(metric.getPath())
                    .message(metric.getMessage())
                    .details(metric.getDetails())
                    .respondedAt(parseDate(response.getRespondedAt()))
                    .build());
        }

        if (response.getErrorCode() != null && !response.getErrorCode().isBlank()) {
            check.setErrorCode(response.getErrorCode());
            check.setErrorMessage(response.getErrorMessage());
        }

        if (check.getReceivedChunks() >= check.getExpectedChunks()) {
            check.setCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
            check.setStatus(aggregateStatus(check.getDeepCheckId()));
        }
        checkRepository.save(check);
    }

    private AgentDeepHealthCheckDto applyTimeoutAndMap(AgentDeepHealthCheckEntity entity) {
        AgentDeepHealthCheckStatus status = entity.getStatus();
        if ((status == AgentDeepHealthCheckStatus.PENDING || status == AgentDeepHealthCheckStatus.IN_PROGRESS)
                && entity.getRequestedAt() != null
                && entity.getRequestedAt().plusMinutes(CHECK_TIMEOUT_MINUTES).isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            status = AgentDeepHealthCheckStatus.TIMED_OUT;
            entity.setStatus(status);
            entity.setCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
            checkRepository.save(entity);
        }
        return AgentDeepHealthCheckDto.builder()
                .deepCheckId(entity.getDeepCheckId())
                .requestId(entity.getRequestId())
                .correlationId(entity.getCorrelationId())
                .status(status)
                .expectedChunks(entity.getExpectedChunks())
                .receivedChunks(entity.getReceivedChunks())
                .requestedAt(entity.getRequestedAt())
                .startedAt(entity.getStartedAt())
                .completedAt(entity.getCompletedAt())
                .lastRespondedAt(entity.getLastRespondedAt())
                .errorCode(entity.getErrorCode())
                .errorMessage(entity.getErrorMessage())
                .build();
    }

    private AgentDeepHealthMetricDto toDto(AgentDeepHealthCheckMetricEntity metric) {
        return AgentDeepHealthMetricDto.builder()
                .metricKey(metric.getMetricKey())
                .metricName(metric.getMetricName())
                .metricGroup(metric.getMetricGroup())
                .status(metric.getStatus())
                .path(metric.getPath())
                .message(metric.getMessage())
                .details(metric.getDetails())
                .respondedAt(metric.getRespondedAt())
                .build();
    }

    private AgentDeepHealthMetricStatus parseMetricStatus(String status) {
        try {
            return AgentDeepHealthMetricStatus.valueOf((status == null ? "ERROR" : status).toUpperCase());
        } catch (Exception ex) {
            return AgentDeepHealthMetricStatus.ERROR;
        }
    }

    private AgentDeepHealthCheckStatus parseCheckStatus(String status) {
        try {
            return AgentDeepHealthCheckStatus.valueOf((status == null ? "SUCCESS" : status).toUpperCase());
        } catch (Exception ex) {
            return AgentDeepHealthCheckStatus.PARTIAL;
        }
    }

    private AgentDeepHealthCheckStatus normalizeChunkStatus(String status) {
        AgentDeepHealthCheckStatus parsed = parseCheckStatus(status);
        if (parsed == AgentDeepHealthCheckStatus.IN_PROGRESS || parsed == AgentDeepHealthCheckStatus.PENDING) {
            return AgentDeepHealthCheckStatus.SUCCESS;
        }
        if (parsed == AgentDeepHealthCheckStatus.TIMED_OUT) {
            return AgentDeepHealthCheckStatus.PARTIAL;
        }
        return parsed;
    }

    private AgentDeepHealthCheckStatus aggregateStatus(String deepCheckId) {
        List<AgentDeepHealthCheckChunkEntity> chunks = chunkRepository.findByDeepCheckIdOrderByChunkIndexAsc(deepCheckId);
        boolean hasPartial = false;
        for (AgentDeepHealthCheckChunkEntity chunk : chunks) {
            if (chunk.getStatus() == AgentDeepHealthCheckStatus.FAILED) {
                return AgentDeepHealthCheckStatus.FAILED;
            }
            if (chunk.getStatus() == AgentDeepHealthCheckStatus.PARTIAL || chunk.getStatus() == AgentDeepHealthCheckStatus.TIMED_OUT) {
                hasPartial = true;
            }
        }
        return hasPartial ? AgentDeepHealthCheckStatus.PARTIAL : AgentDeepHealthCheckStatus.SUCCESS;
    }

    private OffsetDateTime parseDate(String value) {
        if (value == null || value.isBlank()) {
            return OffsetDateTime.now(ZoneOffset.UTC);
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (Exception ex) {
            return OffsetDateTime.now(ZoneOffset.UTC);
        }
    }

    private List<List<String>> chunk(List<String> values, int maxSize) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<List<String>> chunks = new ArrayList<>();
        for (int i = 0; i < values.size(); i += maxSize) {
            chunks.add(values.subList(i, Math.min(values.size(), i + maxSize)));
        }
        return chunks;
    }
}
