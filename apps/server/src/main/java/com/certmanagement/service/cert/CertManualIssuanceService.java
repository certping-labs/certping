// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.dto.cert.TxtRecordDto;
import com.certmanagement.entity.CertManualIssuanceStateEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.constants.ErrorCodes;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.util.MdcIds;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Business logic for the manual certificate issuance flow.
 *
 * <p><b>Flow overview:</b>
 * <ol>
 *   <li>{@link #initiateManualIssuance} — creates a {@code CertificateEntity} (status=PENDING_DNS)
 *       and publishes {@code CERT_MANUAL_TXT_REQUEST} to the agent.</li>
 *   <li>Agent responds via {@code CERT_MANUAL_TXT_RESPONSE} →
 *       {@code CertResponseProcessor.handleManualTxtResponse()} stores state and flips cert to
 *       {@code AWAITING_DNS}.</li>
 *   <li>{@link #getTxtRecords} — UI polls for TXT records once agent has responded.</li>
 *   <li>{@link #triggerValidation} — user confirms DNS records added; publishes
 *       {@code CERT_MANUAL_DNS_VALIDATE} to the agent.</li>
 *   <li>Agent responds via {@code CERT_ISSUANCE_RESPONSE} →
 *       existing {@code handleIssuanceSuccess} flips cert to ACTIVE.</li>
 * </ol>
 *
 * <p><b>Domain credential config behavior:</b> manual flow has no DNS/deployment credentials,
 * so it stores an empty {@code domain_credential_config} (empty dns_config + deployment_targets)
 * for the domain. No {@code RenewalScheduleEntity} is created at issuance time.
 * {@code CertResponseProcessor.createRecoverySchedule()} still skips for manual flow (no
 * renewal schedule in this path), so manual renewal remains out of scope.
 *
 * <p><b>Transaction design (publish-or-fail):</b> DB commit occurs before each queue publish.
 * If publish fails the cert is immediately marked FAILED (or reverted for validation) so it is
 * never left stuck in an intermediate status.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertManualIssuanceService {

    private final CertificateRepository             certificateRepository;
    private final CertManualIssuanceStateRepository stateRepository;
    private final UserDomainCertRepository          udcRepository;
    private final DomainCredentialConfigRepository  domainCredConfigRepository;
    private final CertificateEventRepository        eventRepository;
    private final CertAgentPublisher                publisher;
    private final ObjectMapper                      objectMapper;
    private final CertificateStatusValidator        certificateStatusValidator;
    private final OrgTypeResolver orgTypeResolver;
    /** Writes the request's audit row in this transaction: a publish failure rolls it back with the rest. */
    private final CertificateAuditRecorder certificateAudit;

    // ------------------------------------------------------------------ //
    //  Step 1 — Initiate
    // ------------------------------------------------------------------ //

    /**
     * Creates or reuses a {@link UserDomainCertEntity} for the (organization, domain) pair,
     * then persists a new {@link CertificateEntity} (status=PENDING_DNS) and publishes
     * {@code CERT_MANUAL_TXT_REQUEST} to the agent.
     */
    @Transactional
    public CertificateEntity initiateManualIssuance(Long organizationId, IssueManualRequest req) {
        SanDomainHelper.requireOneRootPerEntry(req.getSanDomainEntries(), IssueManualRequest.SanDomainEntry::getPatterns);
        Integer actorUserId = GatewayRequestContext.getUserId();

        // 1. Upsert UserDomainCertEntity — one stable row per (organization, domain)
        UserDomainCertEntity udc = udcRepository
                .findByOrganizationIdAndDomain(organizationId, req.getDomain())
                .orElseGet(() -> udcRepository.save(
                        UserDomainCertEntity.builder()
                                .organizationId(organizationId)
                                .domain(req.getDomain())
                                .userId(actorUserId)
                                .build()));

        // Manual flow explicitly clears credential routing config for this domain.
        // We keep a stable row with empty values instead of nulls (jsonb columns are NOT NULL).
        upsertEmptyCredentialConfig(udc.getId());

        // 2. Generate xref in the same format as automated issuance
        String certXref = CertificateXrefs.newXref();

        // 3. Build the certificate entity.
        //    Set both userDomainCertId (FK column) and userDomainCert (navigation) so that
        //    cert.getDomain() / cert.getOrganizationId() delegation methods work without a DB reload.
        CertificateEntity cert = CertificateEntity.builder()
                .certificateXref(certXref)
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .wildcard(req.isWildcard())
                .san(req.isSan())
                .sanDomains(extractSanDomains(req.getDomain(), req.isWildcard(), req.getSanDomainEntries()))
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle(null)
                .acmeAccountHandle(req.getAcmeAccountHandle())  // null on first issuance
                .status(CertificateStatus.PENDING_DNS.name())
                .build();
        certificateRepository.save(cert);

        log.info("Manual issuance initiated: xref={}, domain={}, organizationId={}",
                certXref, udc.getDomain(), organizationId);

        // 4. Publish to the queue — if this fails, mark cert FAILED immediately.
        //    Prune patterns within each SAN entry so the agent receives only the minimal set.
        String requestId = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();
        insertEvent(
            cert,
            CertEventType.MANUAL_TXT_REQUESTED.name(),
            null,
            CertificateStatus.PENDING_DNS.name(),
            requestId,
            correlationId,
            actorUserId,
            Map.of(
                "domain", orEmpty(cert.getDomain()),
                "messageType", "CERT_MANUAL_TXT_REQUEST"));
        certificateAudit.manualIssueRequested(cert);

        List<IssueManualRequest.SanDomainEntry> prunedSanEntries = buildPrunedSanEntries(req.getSanDomainEntries());
        try {
            publisher.publishManualTxtRequest(cert,
                    orgTypeResolver.resolve(cert.getOrganizationId()),
                    prunedSanEntries, requestId, correlationId);
        } catch (Exception e) {
            log.error("queue publish failed for CERT_MANUAL_TXT_REQUEST xref={}: {}",
                    certXref, e.getMessage(), e);
            cert.setStatus(CertificateStatus.FAILED.name());
            cert.setLastErrorCode(ErrorCodes.QUEUE_PUBLISH_FAILED);
            cert.setLastErrorMessage(e.getMessage());
            certificateRepository.save(cert);
            insertEvent(
                cert,
                CertEventType.MANUAL_TXT_PUBLISH_FAILED.name(),
                CertificateStatus.PENDING_DNS.name(),
                CertificateStatus.FAILED.name(),
                requestId,
                correlationId,
                actorUserId,
                Map.of(
                    "messageType", "CERT_MANUAL_TXT_REQUEST",
                    "errorCode", ErrorCodes.QUEUE_PUBLISH_FAILED,
                    "errorDetail", e.getMessage() != null ? e.getMessage() : ""));
            throw new ServiceUnavailableException(
                    "Failed to dispatch manual TXT request to cert agent. " +
                    "Cert " + certXref + " has been marked FAILED — please retry.", e);
        }

        return cert;
    }

    // ------------------------------------------------------------------ //
    //  Step 2 — Poll for TXT records
    // ------------------------------------------------------------------ //

    /**
     * Returns the TXT records stored when the agent responded with CERT_MANUAL_TXT_RESPONSE.
     * Returns 404 if the agent has not yet responded. Returns 400 if the ACME order has expired.
     */
    public List<TxtRecordDto> getTxtRecords(String certXref, Long organizationId) {
        certificateRepository
            .findByCertificateXrefAndOrganizationId(certXref, organizationId)
            .orElseThrow(() -> new ResourceNotFoundException(
                "Certificate not found: " + certXref));

        CertManualIssuanceStateEntity state = stateRepository.findByCertXref(certXref)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "TXT records not yet available for certXref=" + certXref));

        if (state.getExpiresAt().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            throw new BadRequestException(
                    "ACME order has expired — please restart issuance via POST /api/v1/certs/issue-manual");
        }

        try {
            return objectMapper.readValue(state.getTxtRecords(), new TypeReference<>() {});
        } catch (Exception e) {
            throw new ServiceUnavailableException(
                    "Failed to deserialize stored TXT records for certXref=" + certXref, e);
        }
    }

    // ------------------------------------------------------------------ //
    //  Step 3 — Trigger DNS validation
    // ------------------------------------------------------------------ //

    /**
     * Updates cert status to VALIDATING and publishes {@code CERT_MANUAL_DNS_VALIDATE} to the agent.
     * Allowed from {@code AWAITING_DNS} (first attempt) or {@code FAILED} (retry after
     * DNS propagation timeout).
     *
    * <p>If queue publish fails, the cert is marked FAILED so the user can retry.
     */
    @Transactional
    public void triggerValidation(String certXref, Long organizationId) {
        CertificateEntity cert = certificateRepository
                .findByCertificateXrefAndOrganizationId(certXref, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Certificate not found: " + certXref));

        String status = cert.getStatus();
        if (!certificateStatusValidator.isAllowedForOperation(
            status,
            CertificateStatusValidator.CertOperation.ISSUE_MANUAL_VALIDATE_DNS)) {
            throw new BadRequestException(
                "Cannot trigger validation from status=" + status
                    + ". Expected "
                    + certificateStatusValidator.allowedStatusesFor(
                        CertificateStatusValidator.CertOperation.ISSUE_MANUAL_VALIDATE_DNS)
                    + ".");
        }

        CertManualIssuanceStateEntity state = stateRepository.findByCertXref(certXref)
                .orElseThrow(() -> new BadRequestException(
                        "No pending manual issuance state for certXref=" + certXref
                        + ". ACME order may have expired — restart from POST /api/v1/certs/issue-manual."));

        if (state.getExpiresAt().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            throw new BadRequestException(
                    "ACME order expired — restart issuance via POST /api/v1/certs/issue-manual");
        }

        cert.setStatus(CertificateStatus.VALIDATING.name());
        certificateRepository.save(cert);

        String requestId = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();
        insertEvent(
            cert,
            CertEventType.MANUAL_DNS_VALIDATE_REQUESTED.name(),
            status,
            CertificateStatus.VALIDATING.name(),
            requestId,
            correlationId,
            GatewayRequestContext.getUserId(),
            Map.of(
                "domain", orEmpty(cert.getDomain()),
                "messageType", "CERT_MANUAL_DNS_VALIDATE"));
        certificateAudit.dnsValidationStarted(cert);

        try {
            publisher.publishManualDnsValidate(cert,
                    orgTypeResolver.resolve(cert.getOrganizationId()),
                    state, requestId, correlationId);
        } catch (Exception e) {
            log.error("queue publish failed for CERT_MANUAL_DNS_VALIDATE xref={}: {}",
                    certXref, e.getMessage(), e);
            cert.setStatus(CertificateStatus.FAILED.name());
            cert.setLastErrorCode(ErrorCodes.QUEUE_PUBLISH_FAILED);
            cert.setLastErrorMessage(e.getMessage());
            certificateRepository.save(cert);
            insertEvent(
                cert,
                CertEventType.MANUAL_DNS_VALIDATE_PUBLISH_FAILED.name(),
                CertificateStatus.VALIDATING.name(),
                CertificateStatus.FAILED.name(),
                requestId,
                correlationId,
                GatewayRequestContext.getUserId(),
                Map.of(
                    "messageType", "CERT_MANUAL_DNS_VALIDATE",
                    "errorCode", ErrorCodes.QUEUE_PUBLISH_FAILED,
                    "errorDetail", e.getMessage() != null ? e.getMessage() : ""));
            throw new ServiceUnavailableException(
                    "Failed to dispatch DNS validation command to cert agent. " +
                "Cert " + certXref + " has been marked FAILED — please retry.", e);
        }

        log.info("DNS validation triggered: xref={}, domain={}", certXref, cert.getDomain());
    }

    private String[] extractSanDomains(String primaryDomain, boolean wildcardPrimary,
                                       List<IssueManualRequest.SanDomainEntry> sanEntries) {
        return SanDomainHelper.buildCertSanDomains(primaryDomain, wildcardPrimary, sanEntries,
                IssueManualRequest.SanDomainEntry::getPatterns);
    }

    /**
     * Returns a copy of {@code sanEntries} with each entry's patterns pruned
     * (wildcard-covered entries removed within the same group).
     */
    private List<IssueManualRequest.SanDomainEntry> buildPrunedSanEntries(
            List<IssueManualRequest.SanDomainEntry> sanEntries) {
        if (sanEntries == null) {
            return List.of();
        }
        List<IssueManualRequest.SanDomainEntry> result = new ArrayList<>();
        for (IssueManualRequest.SanDomainEntry entry : sanEntries) {
            if (entry == null) {
                continue;
            }
            List<String> pruned = SanDomainHelper.pruneWithinGroup(entry.getPatterns());
            if (pruned.isEmpty()) {
                continue;
            }
            IssueManualRequest.SanDomainEntry prunedEntry = new IssueManualRequest.SanDomainEntry();
            prunedEntry.setPatterns(pruned);
            result.add(prunedEntry);
        }
        return result;
    }

    private void insertEvent(CertificateEntity cert,
                             String eventType,
                             String fromStatus,
                             String toStatus,
                             String requestId,
                             String correlationId,
                             Integer userId,
                             Map<String, String> details) {
        if (requestId != null && eventRepository.existsByRequestIdAndEventType(requestId, eventType)) {
            log.info("Duplicate event suppressed for requestId={}, eventType={}, xref={}",
                    requestId, eventType, cert.getCertificateXref());
            return;
        }

        String detailsJson;
        try {
            detailsJson = objectMapper.writeValueAsString(details != null ? details : Map.of());
        } catch (Exception ex) {
            detailsJson = "{}";
        }

        eventRepository.save(CertificateEventEntity.builder()
                .certificateXref(cert.getCertificateXref())
                .organizationId(cert.getOrganizationId())
                .eventType(eventType)
                .fromStatus(fromStatus)
                .toStatus(toStatus)
                .requestId(requestId)
                .correlationId(correlationId)
                .source(EventSource.CERT_MANAGER.value())
                .userId(userId)
                .details(detailsJson)
                .build());
    }

    private String orEmpty(String value) {
        return value != null ? value : "";
    }

        private void upsertEmptyCredentialConfig(Long userDomainCertId) {
                domainCredConfigRepository.findByUserDomainCertId(userDomainCertId)
                                .ifPresentOrElse(existing -> {
                                        existing.setDnsConfig(new LinkedHashMap<>());
                                        existing.setDeploymentTargets(new ArrayList<>());
                                        domainCredConfigRepository.save(existing);
                                }, () -> domainCredConfigRepository.save(
                                                DomainCredentialConfigEntity.builder()
                                                                .userDomainCertId(userDomainCertId)
                                                                .dnsConfig(new LinkedHashMap<>())
                                                                .deploymentTargets(new ArrayList<>())
                                                                .build()
                                ));
        }
}
