// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentHealthResponseDto;
import com.certmanagement.entity.AgentHealthStatusEntity;
import com.certmanagement.entity.Organization;
import com.certmanagement.enums.AgentHealthOverallStatus;
import com.certmanagement.exception.UnknownOrganizationForHeartbeatException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.messaging.model.AgentHealthHeartbeat;
import com.certmanagement.messaging.model.AgentInfo;
import com.certmanagement.repository.AgentHealthStatusRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.audit.MonitoringAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.OffsetDateTime;
import jakarta.persistence.OptimisticLockException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AgentHealthService {

    private static final int DEFAULT_HEARTBEAT_CADENCE_MINUTES = 5;
    private static final int MIN_HEARTBEAT_CADENCE_MINUTES = 1;
    private static final int MAX_HEARTBEAT_CADENCE_MINUTES = 60;
    private static final int MISSED_HEARTBEATS_FOR_STALE = 2;
    private static final int MAX_HEARTBEAT_PERSIST_ATTEMPTS = 5;
    private static final long HEARTBEAT_PERSIST_BASE_BACKOFF_MS = 20L;

    private final OrganizationRepository organizationRepository;
    private final AgentHealthStatusRepository agentHealthStatusRepository;
    private final CertAgentPublisher certAgentPublisher;
    private final PlatformTransactionManager transactionManager;
    /** The cadence row of the audit trail, written in the change's transaction. */
    private final MonitoringAuditRecorder monitoringAudit;
    /** Where each agent's CA status goes; set by Spring, absent in unit tests that do not cover it. */
    private AgentCaStatusStore caStatusStore;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setCaStatusStore(AgentCaStatusStore caStatusStore) {
        this.caStatusStore = caStatusStore;
    }

    /**
     * Stores the CA status a heartbeat carried, for the agent whose token delivered it. Scoped to the
     * organization the gateway authenticated, never to the one in the body. A failure is logged: the
     * heartbeat itself is already saved.
     */
    public void saveCaStatus(String verifiedOrganizationId, Long agentTokenId, AgentCaStatus caStatus) {
        if (caStatus == null || caStatusStore == null) {
            return;
        }
        try {
            caStatusStore.save(Long.parseLong(verifiedOrganizationId), agentTokenId, caStatus);
        } catch (RuntimeException e) {
            log.warn("Could not store the CA status for organizationId={} agentTokenId={}: {}",
                    verifiedOrganizationId, agentTokenId, e.getMessage());
        }
    }

    /** Where each agent's last heartbeat and info go; set by Spring, absent in unit tests that do not cover it. */
    private AgentInfoStore agentInfoStore;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setAgentInfoStore(AgentInfoStore agentInfoStore) {
        this.agentInfoStore = agentInfoStore;
    }

    /**
     * Records a heartbeat for the agent whose token delivered it, with the info it carried (null for
     * an older agent). Scoped to the organization the gateway authenticated. A failure is logged:
     * the heartbeat itself is already saved.
     */
    public void saveAgentInfo(String verifiedOrganizationId, Long agentTokenId, AgentInfo agentInfo) {
        if (agentTokenId == null || agentInfoStore == null || verifiedOrganizationId == null) {
            return;
        }
        try {
            agentInfoStore.recordHeartbeat(Long.parseLong(verifiedOrganizationId), agentTokenId, agentInfo);
        } catch (RuntimeException e) {
            log.warn("Could not store the agent info for organizationId={} agentTokenId={}: {}",
                    verifiedOrganizationId, agentTokenId, e.getMessage());
        }
    }

    /**
     * Retries on optimistic lock failure: concurrent heartbeats for the same org update
     * {@link AgentHealthStatusEntity} with the same id/version.
     *
     * @return {@code false} if the message was ignored (unparseable organizationId); {@code true} if persistence ran
     * @throws UnknownOrganizationForHeartbeatException if the organization id is valid but not found in the DB
     */
    public boolean saveHeartbeat(AgentHealthHeartbeat response) {
        Long organizationId;
        try {
            organizationId = Long.parseLong(response.getOrganizationId());
        } catch (Exception ex) {
            log.warn("Ignoring AGENT_HEALTH_HEARTBEAT with invalid organizationId='{}'", response.getOrganizationId());
            return false;
        }

        TransactionTemplate tx = newTransactionTemplate();

        for (int attempt = 1; attempt <= MAX_HEARTBEAT_PERSIST_ATTEMPTS; attempt++) {
            try {
                final Long orgId = organizationId;
                tx.executeWithoutResult(status -> persistHeartbeatPayload(orgId, response));
                return true;
            } catch (Exception ex) {
                if (attempt < MAX_HEARTBEAT_PERSIST_ATTEMPTS && isOptimisticLockFailure(ex)) {
                    log.warn(
                            "Optimistic lock persisting agent health, retrying ({}/{}) for organizationId={}: {}",
                            attempt,
                            MAX_HEARTBEAT_PERSIST_ATTEMPTS,
                            organizationId,
                            ex.getClass().getSimpleName());
                    sleepForHeartbeatRetry(attempt);
                } else {
                    throw ex;
                }
            }
        }
        throw new IllegalStateException("Heartbeat save attempts exhausted without result");
    }

    private TransactionTemplate newTransactionTemplate() {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return tx;
    }

    private void persistHeartbeatPayload(Long organizationId, AgentHealthHeartbeat response) {
        Organization organization = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new UnknownOrganizationForHeartbeatException(organizationId));
        reconcileCadenceFromHeartbeat(organization, response.getHeartbeatCadenceMinutes());

        AgentHealthStatusEntity entity = agentHealthStatusRepository.findById(organizationId)
                .orElseGet(() -> AgentHealthStatusEntity.builder().organizationId(organizationId).build());

        entity.setListening(response.getListening());
        entity.setAgentCheckedAt(parseOffsetDateTime(response.getRespondedAt()));
        entity.setCmsReceivedAt(OffsetDateTime.now());
        entity.setOverallStatus(Boolean.TRUE.equals(response.getListening())
                ? AgentHealthOverallStatus.HEALTHY
                : AgentHealthOverallStatus.UNHEALTHY);
        entity.setLastErrorCode(Boolean.TRUE.equals(response.getListening()) ? null : "AGENT_NOT_LISTENING");
        entity.setLastErrorMessage(Boolean.TRUE.equals(response.getListening()) ? null : "Agent reported not listening");

        agentHealthStatusRepository.save(entity);
    }

    @Transactional(readOnly = true)
    public AgentHealthStatusEntity getOrganizationHealth(Long organizationId) {
        return agentHealthStatusRepository.findById(organizationId).orElse(null);
    }

    @Transactional(readOnly = true)
    public AgentHealthResponseDto getOrganizationHealthView(Long organizationId) {
        AgentHealthStatusEntity entity = getOrganizationHealth(organizationId);
        int cadenceMinutes = getHeartbeatCadenceMinutes(organizationId);

        if (entity == null) {
            return AgentHealthResponseDto.builder()
                    .organizationId(organizationId)
                    .overallStatus(AgentHealthOverallStatus.UNKNOWN)
                    .listening(null)
                    .checkedAt(null)
                    .stale(true)
                    .failureReason("No heartbeat received yet")
                    .build();
        }

        boolean stale = isStale(entity.getCmsReceivedAt(), cadenceMinutes);
        AgentHealthOverallStatus overallStatus = stale
                ? AgentHealthOverallStatus.UNHEALTHY
                : (Boolean.TRUE.equals(entity.getListening())
                    ? AgentHealthOverallStatus.HEALTHY
                    : AgentHealthOverallStatus.UNHEALTHY);
        String failureReason = stale
                ? "Missed " + MISSED_HEARTBEATS_FOR_STALE + " heartbeats (cadence " + cadenceMinutes + " minutes)"
                : (Boolean.TRUE.equals(entity.getListening()) ? null : "Agent reported not listening");

        return AgentHealthResponseDto.builder()
                .organizationId(entity.getOrganizationId())
                .overallStatus(overallStatus)
                .listening(entity.getListening())
                .checkedAt(entity.getAgentCheckedAt())
                .stale(stale)
                .failureReason(failureReason)
                .build();
    }

    @Transactional(readOnly = true)
    public int getHeartbeatCadenceMinutes(Long organizationId) {
        Organization organization = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found: " + organizationId));
        Integer value = organization.getAgentHeartbeatCadenceMinutes();
        return value != null ? value : DEFAULT_HEARTBEAT_CADENCE_MINUTES;
    }

    @Transactional
    public int updateHeartbeatCadenceMinutes(Long organizationId, int minutes) {
        if (minutes < MIN_HEARTBEAT_CADENCE_MINUTES || minutes > MAX_HEARTBEAT_CADENCE_MINUTES) {
            throw new IllegalArgumentException(
                    "heartbeatCadenceMinutes must be between " + MIN_HEARTBEAT_CADENCE_MINUTES + " and " + MAX_HEARTBEAT_CADENCE_MINUTES);
        }
        Organization organization = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found: " + organizationId));
        Integer before = organization.getAgentHeartbeatCadenceMinutes();
        organization.setAgentHeartbeatCadenceMinutes(minutes);
        organizationRepository.save(organization);
        if (before == null || before != minutes) {
            monitoringAudit.heartbeatCadenceChanged(organizationId, before, minutes);
        }
        certAgentPublisher.publishHeartbeatCadenceUpdate(
                organizationId.toString(), organization.getOrgType(), minutes);
        return minutes;
    }

    private OffsetDateTime parseOffsetDateTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (Exception ex) {
            return null;
        }
    }

    private boolean isStale(OffsetDateTime cmsReceivedAt, int cadenceMinutes) {
        if (cmsReceivedAt == null) {
            return true;
        }
        long staleAfterMinutes = (long) cadenceMinutes * MISSED_HEARTBEATS_FOR_STALE;
        return Duration.between(cmsReceivedAt, OffsetDateTime.now()).toMinutes() >= staleAfterMinutes;
    }

    /**
     * If the agent-reported cadence does not match {@code organizations.agent_heartbeat_cadence_minutes},
     * schedule {@code AGENT_HEARTBEAT_CADENCE_UPDATE} <em>after this transaction commits</em> so the
     * message is not sent if the heartbeat row fails to persist. Does not change the org row.
     */
    private void reconcileCadenceFromHeartbeat(Organization organization, Integer reportedMinutes) {
        if (reportedMinutes == null) {
            return;
        }
        if (reportedMinutes < MIN_HEARTBEAT_CADENCE_MINUTES || reportedMinutes > MAX_HEARTBEAT_CADENCE_MINUTES) {
            return;
        }
        Long organizationId = organization.getId();
        int dbMinutes = organization.getAgentHeartbeatCadenceMinutes() != null
                ? organization.getAgentHeartbeatCadenceMinutes()
                : DEFAULT_HEARTBEAT_CADENCE_MINUTES;
        if (dbMinutes == reportedMinutes) {
            return;
        }
        log.info(
                "Agent-reported cadence {}m out of sync with DB {}m for organizationId={};"
                        + " scheduling AGENT_HEARTBEAT_CADENCE_UPDATE after commit",
                reportedMinutes,
                dbMinutes,
                organizationId);
        String orgIdForMessage = organizationId.toString();
        registerPublishCadenceUpdateAfterCommit(orgIdForMessage, organization.getOrgType(), dbMinutes);
    }

    private void registerPublishCadenceUpdateAfterCommit(String organizationId, String orgType, int dbMinutes) {
        Runnable publish = () -> {
            try {
                certAgentPublisher.publishHeartbeatCadenceUpdate(organizationId, orgType, dbMinutes);
            } catch (Exception e) {
                log.error(
                        "Failed to publish AGENT_HEARTBEAT_CADENCE_UPDATE after heartbeat commit for organizationId={}: {}",
                        organizationId,
                        e.getMessage(),
                        e);
            }
        };
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    publish.run();
                }
            });
        } else {
            log.warn(
                    "No active transaction synchronization; publishing AGENT_HEARTBEAT_CADENCE_UPDATE immediately for organizationId={}",
                    organizationId);
            publish.run();
        }
    }

    private static void sleepForHeartbeatRetry(int attempt) {
        try {
            Thread.sleep(HEARTBEAT_PERSIST_BASE_BACKOFF_MS * attempt);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while retrying heartbeat save", e);
        }
    }

    /**
     * Detects JPA / Hibernate optimistic lock and Spring wrappers on concurrent updates to
     * {@code agent_health_status.version}. Package-private for tests.
     */
    static boolean isOptimisticLockFailure(Throwable ex) {
        for (Throwable cur = ex; cur != null; cur = cur.getCause()) {
            if (cur instanceof OptimisticLockingFailureException) {
                return true;
            }
            if (cur instanceof OptimisticLockException) {
                return true;
            }
            if (cur instanceof org.hibernate.StaleObjectStateException) {
                return true;
            }
        }
        return false;
    }
}
