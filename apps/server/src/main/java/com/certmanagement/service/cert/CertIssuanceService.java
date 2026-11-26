// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.CertDeployRequest;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.CertRenewalRequest;
import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.constants.ErrorCodes;
import com.certmanagement.constants.ExpiringCertsConstants;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.enums.CaAccountSource;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.KeyCustody;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.PublishOutcome;
import com.certmanagement.messaging.model.CertIssuanceCommand;
import com.certmanagement.messaging.model.CertRenewalCommand;
import com.certmanagement.messaging.model.CertRevocationCommand;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import com.certmanagement.util.MdcIds;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Certificate lifecycle business logic.
 *
 * <p><b>Transaction design</b>: {@code issue()}, {@code renew()}, and {@code deploy()} are
 * intentionally <em>not</em> annotated with {@code @Transactional} at the method level.
 * Instead, each method delegates all DB writes to {@link CertPersistenceService}, which runs
 * them in its own committed transaction <em>before</em> the queue publish is attempted.
 *
 * <p>This avoids the classic dual-write race where the queued message is sent inside a still-open
 * DB transaction: if the commit then fails, the agent has already received the command but the
 * cert record never lands in the database.
 *
 * <p>If the queue publish fails <em>after</em> the DB commit, a second call to the appropriate
 * {@code markXxxPublishFailed} method updates the cert to FAILED in a fresh transaction, so it
 * is never left stuck in PENDING / RENEWING / DEPLOYING.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertIssuanceService {

        public record CredentialRefs(
                        Map<String, String> dnsConfigXref,
                        List<String> deploymentCredentialXrefs,
                        String dnsCredentialKvPath,
                        List<String> deploymentCredentialKvPaths) {
                public CredentialRefs(Map<String, String> dnsConfigXref, List<String> deploymentCredentialXrefs) {
                        this(dnsConfigXref, deploymentCredentialXrefs, null, Collections.emptyList());
                }
        }

    private static final CredentialRefs EMPTY_CREDENTIAL_REFS =
            new CredentialRefs(Collections.emptyMap(), Collections.emptyList(), null, Collections.emptyList());

    private final CertificateRepository          certificateRepository;
    private final RenewalScheduleRepository      renewalScheduleRepository;
    private final DomainCredentialConfigRepository domainCredConfigRepository;
    private final com.certmanagement.repository.CertDeploymentConfigRepository certDeploymentConfigRepository;
    private final UserDomainCertRepository        udcRepository;
    private final CredentialReferenceService      credentialService;
    private final DomainCredentialConfigService   domainCredConfigService;
    private final CertPersistenceService          persistenceService;
    private final CertAgentPublisher              publisher;
    private final CertificateStatusValidator      certificateStatusValidator;
    private final DeploymentExecutionService      deploymentExecutionService;
    private final KubernetesDeploymentConfigResolver kubernetesDeploymentConfigResolver;
    private final CertDeploymentConfigService certDeploymentConfigService;
    private final RenewalDraftHelper              renewalDraftHelper;
    private final FeatureFlagService              featureFlagService;
    private final OrgTypeResolver orgTypeResolver;

    /**
     * Runs the issuance writes in one transaction. Optional: absent in unit tests that build this service
     * without it, where the writes then run as they come.
     */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private org.springframework.transaction.support.TransactionTemplate transactionTemplate;

    void setTransactionTemplate(org.springframework.transaction.support.TransactionTemplate transactionTemplate) {
        this.transactionTemplate = transactionTemplate;
    }

    private <T> T inTransaction(java.util.function.Supplier<T> work) {
        return transactionTemplate == null ? work.get() : transactionTemplate.execute(status -> work.get());
    }

    // ------------------------------------------------------------------ //
    //  Issue
    // ------------------------------------------------------------------ //

    public CertificateEntity issue(Long organizationId, CertIssuanceRequest request) {
        SanDomainHelper.requireOneRootPerEntry(request.getSanDomainEntries(),
                CertIssuanceRequest.SanDomainEntry::getPatterns);
        // Check the CA feature flag before doing any work
        if (request.getCaProvider() != null) {
            featureFlagService.assertCaEnabled(toCaFeatureKey(request.getCaProvider()), organizationId);
        }

        // 1. Resolve & validate primary DNS credential
        CredentialReferenceEntity primaryDnsCred = resolveDnsCredential(organizationId, request.getDnsCredentialXref());

        // 2. Resolve & validate all SAN DNS credentials upfront (fail fast)
        List<CertIssuanceRequest.SanDomainEntry> sanRequests =
                request.getSanDomainEntries() != null ? request.getSanDomainEntries() : List.of();
        Map<CertIssuanceRequest.SanDomainEntry, CredentialReferenceEntity> sanCredMap = new LinkedHashMap<>();
        for (CertIssuanceRequest.SanDomainEntry sanReq : sanRequests) {
            sanCredMap.put(sanReq, resolveDnsCredential(organizationId, sanReq.getDnsCredentialXref()));
        }

        // 3. Resolve & validate all deployment credentials
        List<String> deploymentTargets = request.getDeploymentTargets() != null
                ? request.getDeploymentTargets() : List.of();
        Map<String, CredentialReferenceEntity> deploymentCredByXref = new LinkedHashMap<>();
        for (String credXref : deploymentTargets) {
            CredentialReferenceEntity c = resolveActiveCredential(organizationId, credXref);
            if (!"DEPLOYMENT".equals(c.getType())) {
                throw new BadRequestException(
                        "Credential '" + credXref + "' in deploymentTargets must be type DEPLOYMENT, found: " + c.getType());
            }
            deploymentCredByXref.put(credXref, c);
        }

        // 4. Resolve optional ACME + CA credentials.
        CredentialReferenceEntity acme = resolveOptionalCredential(organizationId, request.getAcmeCredentialXref());
        CredentialReferenceEntity ca   = resolveCaCredential(organizationId, request.getCaProvider(), request.getCaCredentialXref());

        // 5. Build CertIssuanceCommand SAN entries (resolved provider + secretHandle + patterns)
        List<CertIssuanceCommand.SanDomainEntry> sanCommandEntries = buildCommandSanEntries(sanCredMap);

        // 6. Build dns_config map for DomainCredentialConfigEntity
        Map<String, String> dnsConfig = buildDnsConfigMap(
                request.getDomain(), request.getDnsCredentialXref(), sanRequests);

        // 7. Generate xrefs
        String certXref      = CertificateXrefs.newXref();
        String requestId     = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();  // from frontend via MDC; null on scheduler

        // 8-10 in one transaction, committed before the publish: when anything in it fails (a 409 on a
        // duplicate key, a 423 from a feature lock) the user_domain_certificate row created here and the
        // deployment configs are rolled back with it, so no orphan row is left behind.
        CertificateEntity cert = inTransaction(() -> {
            // 8. Create or reuse UserDomainCertEntity
            UserDomainCertEntity udc = udcRepository
                    .findByOrganizationIdAndDomain(organizationId, request.getDomain())
                    .orElseGet(() -> udcRepository.save(UserDomainCertEntity.builder()
                            .organizationId(organizationId)
                            .domain(request.getDomain())
                            .userId(GatewayRequestContext.getUserId())
                            .build()));

            applyAutomatedDeploymentConfigs(
                    organizationId,
                    udc.getId(),
                    deploymentTargets,
                    deploymentCredByXref,
                    request.getDeploymentTargetConfigs(),
                    request.getDomain());

            // 9. Build entities
            CertificateEntity issued = buildIssuanceCert(udc, certXref, request, acme, ca);

            DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                    .userDomainCertId(udc.getId())
                    .dnsConfig(new LinkedHashMap<>(dnsConfig))
                    .deploymentTargets(new ArrayList<>(deploymentTargets))
                    .build();

            RenewalScheduleEntity schedule = buildIssuanceSchedule(certXref, request, acme, ca);

            // 10. Commit: credConfig first (schedule FK references it), then cert + schedule
            persistenceService.persistIssuance(issued, credConfig, schedule, requestId, correlationId);
            return issued;
        });

        // 11. Build and publish command
        CertIssuanceCommand command = CertIssuanceCommand.builder()
                .organizationId(organizationId.toString())
                .orgType(orgTypeResolver.resolve(organizationId))
                .requestId(requestId)
                .correlationId(correlationId)
                .certificateXref(certXref)
                .domain(request.getDomain())
                .wildcard(request.getWildcard())
                .san(request.getSan())
                .caProvider(request.getCaProvider())
                .validityDays(request.getValidityDays())
                .dnsProvider(primaryDnsCred.getProvider())
                .dnsCredentialHandle(primaryDnsCred.getSecretHandle())
                .dnsCredentialConfigJson(primaryDnsCred.getConfigJson())
                .acmeAccountHandle(acme != null ? acme.getSecretHandle() : null)
                .caCredentialHandle(ca   != null ? ca.getSecretHandle()  : null)
                .sanDomainEntries(sanCommandEntries.isEmpty() ? null : sanCommandEntries)
                .caOptions(request.getCaOptions())
                .build();

        publishIssuanceOrFail(command, certXref, organizationId, requestId, correlationId);
        log.info("Cert issuance submitted: xref={}, domain={}, organizationId={}, dnsProvider={}",
                certXref, request.getDomain(), organizationId, primaryDnsCred.getProvider());
        return cert;
    }

    private void applyAutomatedDeploymentConfigs(
            Long organizationId,
            Long userDomainCertId,
            List<String> deploymentTargets,
            Map<String, CredentialReferenceEntity> deploymentCredByXref,
            List<CertIssuanceRequest.DeploymentTargetConfigEntry> deploymentTargetConfigs,
            String domain) {
        if (deploymentTargets == null || deploymentTargets.isEmpty()) {
            if (deploymentTargetConfigs != null && !deploymentTargetConfigs.isEmpty()) {
                log.info("Ignoring deploymentTargetConfigs because deploymentTargets is empty for domain={}", domain);
            }
            return;
        }
        if (deploymentTargetConfigs == null || deploymentTargetConfigs.isEmpty()) {
            return;
        }
        for (CertIssuanceRequest.DeploymentTargetConfigEntry entry : deploymentTargetConfigs) {
            String credXref = entry.getDeploymentCredentialXref();
            if (credXref == null || credXref.isBlank()) {
                throw new BadRequestException("deploymentTargetConfigs.deploymentCredentialXref is required");
            }
            if (!deploymentTargets.contains(credXref)) {
                throw new BadRequestException(
                        "deploymentTargetConfigs credXref '" + credXref + "' must also be present in deploymentTargets");
            }
            CredentialReferenceEntity deployCred = deploymentCredByXref.get(credXref);
            if (deployCred == null) {
                throw new BadRequestException(
                        "deploymentTargetConfigs credXref '" + credXref + "' must reference an active deployment credential");
            }

            // Kubernetes-specific: use the legacy config (nsSecretMap) path
            if ("KUBERNETES_SECRETS".equals(deployCred.getProvider()) && entry.getConfig() != null) {
                kubernetesDeploymentConfigResolver.resolveOrUpsert(
                        organizationId,
                        userDomainCertId,
                        deployCred,
                        entry.getConfig().getUseDefault(),
                        entry.getConfig().getNsSecretMap(),
                        domain + ":" + credXref);
                continue;
            }

            // Generic non-Kubernetes: persist targets via the generic envelope path
            if (entry.getTargets() != null && !entry.getTargets().isNull()) {
                certDeploymentConfigService.upsertGenericTargets(
                        organizationId,
                        userDomainCertId,
                        deployCred,
                        entry.getTargets());
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Renew
    // ------------------------------------------------------------------ //

    public CertificateEntity renew(Long organizationId, String certificateXref, CertRenewalRequest request) {
        CertificateEntity cert = getCertForOrganization(organizationId, certificateXref);
        certificateStatusValidator.validateForManualRenewal(cert, certificateXref);

        if (cert.getKeyCustody() == KeyCustody.CUSTOMER_HELD) {
            throw new BadRequestException(AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(cert.getSpecialCertificateType())
                    ? "Certificate '" + certificateXref + "' is an AKAMAI_CPS special certificate. "
                        + "Akamai holds the private key; renewal is handled automatically by the scheduler, or trigger it "
                        + "by removing and re-adding the AKAMAI_CPS deployment target on the domain credential config."
                    : "Certificate '" + certificateXref + "' was issued for a key CertPing does not hold; "
                        + "request a new certificate instead of renewing this one.");
        }

        // Load renewal schedule for operational fields
        RenewalScheduleEntity schedule = renewalScheduleRepository
                .findByCertificateXref(certificateXref)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No renewal schedule found for xref=" + certificateXref));

        // Load LIVE credential config
        DomainCredentialConfigEntity credConfig =
                domainCredConfigService.getById(schedule.getDomainCredentialConfigId());

        List<String> replacementTargets = request == null || request.getDeploymentTargets() == null
                || request.getDeploymentTargets().isEmpty() ? null : request.getDeploymentTargets();
        if (replacementTargets != null) {
            for (String credXref : replacementTargets) {
                CredentialReferenceEntity c = resolveActiveCredential(organizationId, credXref);
                if (!"DEPLOYMENT".equals(c.getType())) {
                    throw new BadRequestException(
                            "deploymentTargets credXref '" + credXref + "' must be type DEPLOYMENT");
                }
            }
        }

        // Load UserDomainCert to get domain + wildcard context
        UserDomainCertEntity udc = udcRepository.findById(cert.getUserDomainCertId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "UserDomainCert not found for cert xref=" + certificateXref));

        // Resolve DNS credentials from live config (dns_config keys are root domains).
        String primaryCredXref = SanDomainHelper.lookupRootCredXref(
                credConfig.getDnsConfig(), udc.getDomain());
        if (primaryCredXref == null) {
            throw new ResourceNotFoundException(
                    "No DNS credential configured for primary domain '" + udc.getDomain() + "'");
        }
        CredentialReferenceEntity primaryDnsCred = resolveActiveCredential(organizationId, primaryCredXref);

        List<CertRenewalCommand.SanDomainEntry> sanEntries =
                renewalDraftHelper.buildRenewalSanEntriesFromConfig(
                        udc.getDomain(),
                        cert.getSanDomains(),
                        credConfig.getDnsConfig(),
                        primaryDnsCred,
                        xref -> resolveActiveCredential(organizationId, xref));

        String prevStatus    = cert.getStatus();
        String requestId     = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();  // from frontend via MDC; null on scheduler

        String renewedXref = CertificateXrefs.newXref();
        String renewedCertSecretHandle = renewalDraftHelper.deriveRenewedCertSecretHandle(
                schedule.getCertSecretHandle(), cert.getCertSecretHandle(), renewedXref);
        CertificateEntity renewedDraft = renewalDraftHelper.buildRenewedDraft(cert, renewedXref, renewedCertSecretHandle);

        CertPersistenceService.RenewalPersistResult persistResult =
                persistenceService.persistRenewal(cert, renewedDraft, credConfig, replacementTargets,
                        prevStatus, requestId, correlationId);

        CertRenewalCommand command = renewalDraftHelper.buildRenewalCommand(
                cert,
                renewedDraft,
                schedule,
                udc.getDomain(),
                organizationId,
                orgTypeResolver.resolve(organizationId),
                requestId,
                correlationId,
                primaryDnsCred,
                sanEntries);

        publishRenewalOrFail(command, certificateXref, renewedXref, organizationId, prevStatus, requestId, correlationId);
        log.info("Cert renewal submitted: xref={}, domain={}, organizationId={}",
                certificateXref, udc.getDomain(), organizationId);
        return persistResult.getPreviousCert();
    }

    // ------------------------------------------------------------------ //
    //  Deploy
    // ------------------------------------------------------------------ //

    public CertificateEntity deploy(Long organizationId, String certificateXref, CertDeployRequest request) {
        CertificateEntity cert = getCertForOrganization(organizationId, certificateXref);
        validateDeployPreconditions(cert, certificateXref);

        CredentialReferenceEntity deployCred =
                resolveActiveCredential(organizationId, request.getDeploymentCredentialXref());
        validateDeployCredential(deployCred, request);
        String configJsonOverride = resolveManualDeploymentConfig(organizationId, cert, deployCred, request);

        String requestId     = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();  // from frontend via MDC; null on scheduler
        persistenceService.persistDeployment(
                cert, cert.getStatus(), requestId, correlationId,
                request.getTargetType().name(), "");

        deploymentExecutionService.dispatchSingle(
                organizationId, cert, cert.getCertSecretHandle(),
                request.getDeploymentCredentialXref(), deployCred,
                requestId, correlationId, "MANUAL", configJsonOverride);

        log.info("Cert deployment submitted: xref={}, targetType={}, organizationId={}",
                certificateXref, request.getTargetType(), organizationId);
        return cert;
    }

    // ------------------------------------------------------------------ //
    //  Read
    // ------------------------------------------------------------------ //

    @Transactional(readOnly = true)
    public CertificateEntity getStatus(Long organizationId, String certificateXref) {
        return getCertForOrganization(organizationId, certificateXref);
    }

    @Transactional(readOnly = true)
    public Page<CertificateEntity> list(Long organizationId, String status, String domain, int page, int size) {
        PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "updatedAt"));
        return list(organizationId, status, domain, pageable);
    }

    @Transactional(readOnly = true)
    public Page<CertificateEntity> list(Long organizationId, String status, String domain, Pageable pageable) {
        Pageable effectivePageable = pageable;
        if (pageable == null || pageable.getSort().isUnsorted()) {
            int pageNumber = pageable != null ? pageable.getPageNumber() : 0;
            int pageSize = pageable != null ? pageable.getPageSize() : 20;
            effectivePageable = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "updatedAt"));
        }

        String statusFilter = (status != null && !status.isBlank())
                ? status.toUpperCase()
                : null;
        String domainFilter = (domain != null && !domain.isBlank())
                ? domain
                : null;
        String domainPattern = (domainFilter != null)
                ? "%" + domainFilter.toLowerCase(Locale.ROOT) + "%"
                : null;

        return certificateRepository.findLatestByOrganizationAndFilters(
                organizationId,
                statusFilter,
                domainPattern,
                effectivePageable);
    }

    @Transactional(readOnly = true)
    public Page<CertificateEntity> history(Long organizationId, Long userDomainCertId, int page, int size) {
        PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "updatedAt"));
        return history(organizationId, userDomainCertId, pageable);
    }

    @Transactional(readOnly = true)
    public Page<CertificateEntity> history(Long organizationId, Long userDomainCertId, Pageable pageable) {
        Pageable effectivePageable = pageable;
        if (pageable == null || pageable.getSort().isUnsorted()) {
            int pageNumber = pageable != null ? pageable.getPageNumber() : 0;
            int pageSize = pageable != null ? pageable.getPageSize() : 20;
            effectivePageable = PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.DESC, "updatedAt"));
        }

        return certificateRepository.findHistoryByOrganizationAndUserDomainCertId(
                organizationId,
                userDomainCertId,
                effectivePageable);
    }

    // ------------------------------------------------------------------ //
    //  Expiring (assistant)
    // ------------------------------------------------------------------ //

    /**
     * ACTIVE certs whose {@code validTo} falls in {@code [now, now+withinDays]} (UTC), matching
     * the dashboard window style. Soft-delete and ordering live in the repository query.
     *
     * <p>A null {@code pageable} becomes
     * {@code PageRequest.of(ExpiringCertsConstants.DEFAULT_PAGE, ExpiringCertsConstants.DEFAULT_PAGE_SIZE)}.
     */
    @Transactional(readOnly = true)
    public Slice<CertificateRepository.ExpiringCertificateRow> listExpiring(
            Long organizationId, int withinDays, Pageable pageable) {
        if (withinDays < ExpiringCertsConstants.MIN_WITHIN_DAYS
                || withinDays > ExpiringCertsConstants.MAX_WITHIN_DAYS) {
            throw new BadRequestException(
                    "withinDays must be between "
                            + ExpiringCertsConstants.MIN_WITHIN_DAYS
                            + " and "
                            + ExpiringCertsConstants.MAX_WITHIN_DAYS);
        }
        OffsetDateTime from = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime to = from.plusDays(withinDays);
        Pageable effectivePageable = pageable != null
                ? pageable
                : PageRequest.of(
                        ExpiringCertsConstants.DEFAULT_PAGE,
                        ExpiringCertsConstants.DEFAULT_PAGE_SIZE);
        return certificateRepository.findExpiringBetween(
                organizationId, from, to, effectivePageable);
    }

    // ------------------------------------------------------------------ //
    //  Delete (soft)
    // ------------------------------------------------------------------ //

    /**
     * @deprecated Per-cert soft-delete leaves the parent {@code user_domain_certificate}
     *     and its {@code domain_credential_config} / {@code cert_deployment_config} rows
     *     alive. Prefer {@link #deleteUserDomainCert} which cascades every cert iteration
     *     on the domain plus the per-domain config rows in one transactional sweep.
     *     {@code CertExpiryCleanupService} also auto-soft-deletes EXPIRED / REVOKED certs
     *     24h after they enter that state, so the manual per-cert path is rarely needed.
     *     Will be removed in a future release.
     */
    @Deprecated
    @Transactional
    public void delete(Long organizationId, String certificateXref) {
                CertificateEntity cert = getCertForOrganization(organizationId, certificateXref);
                certificateStatusValidator.validateForOperation(
                                cert,
                                certificateXref,
                                CertificateStatusValidator.CertOperation.DELETE);
                int updated = persistenceService.softDeleteAndInsertEvent(
                                certificateXref,
                                organizationId,
                                cert.getStatus(),
                                MdcIds.requestId(),
                                MdcIds.correlationId());
        if (updated == 0) {
            throw new ResourceNotFoundException(
                    "Certificate '" + certificateXref + "' not found or already deleted for organization");
        }

        log.info("Certificate soft-deleted: xref={}, organizationId={}", certificateXref, organizationId);
    }

    /**
     * Cascade-delete an entire managed domain (UserDomainCert). The middle layer
     * between {@link #delete} (per-cert) and {@code OrganizationService.deleteOrganization}
     * (whole tenant): wipes every cert iteration that ever existed on this domain plus the
     * per-domain credential / deployment configs that those certs share.
     *
     * <p>Order matters: cert-level rows first via the existing per-cert path (so events
     * are inserted, agent KV delete published), then the per-UDC
     * rows that survived because they're keyed by UDC instead of by cert, then the UDC
     * itself. Everything is soft — no row is physically removed.
     *
     * <p>Org scope is enforced at every step: the initial UDC lookup, the per-cert
     * fetch, and the final UDC update all carry {@code organizationId}, so a cross-org
     * caller can never reach another tenant's domain even if they guess the id.
     */
    @Transactional
    public void deleteUserDomainCert(Long organizationId, Long userDomainCertId) {
        // Ownership check + early 404. UserDomainCertRepository.findById is fine for
        // existence; the soft-delete UPDATE at the end is what enforces org scope on write.
        UserDomainCertEntity udc = udcRepository.findById(userDomainCertId)
                .filter(u -> organizationId.equals(u.getOrganizationId()))
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Managed domain '" + userDomainCertId + "' not found for organization"));

        // Fan out per-cert delete. Each call reuses the existing single-cert cascade
        // (renewal_schedule, deployments, manual_issuance, events, KV-delete
        // command publish). Done one-by-one so the audit trail lists every
        // CERT_DELETED event (and one certificate.deleted row per certificate) and the agent
        // publish stays idempotent per cert. The whole fan-out is this one transaction: it never
        // partly succeeds, so a failure is the request's one failure row (@AuditFailure).
        List<CertificateRepository.CertificateXrefStatus> activeCerts = certificateRepository
                .findActiveByUserDomainCertIdAndOrganizationId(userDomainCertId, organizationId);
        for (CertificateRepository.CertificateXrefStatus cert : activeCerts) {
            // Bypass status validation — once we've decided to nuke the domain, even
            // PENDING / REVOKE_PENDING certs go. Mirrors deleteRevoked's reasoning.
            persistenceService.softDeleteAndInsertEvent(
                    cert.getCertificateXref(),
                    organizationId,
                    cert.getStatus(),
                    MdcIds.requestId(),
                    MdcIds.correlationId(),
                    CertificateAuditRecorder.SOURCE_MANAGED_DOMAIN);
        }

        // Per-UDC tables that single-cert delete leaves alone because they span all
        // cert iterations on the same domain. Now that we're killing the domain itself,
        // they go too.
        int dccUpdated = domainCredConfigRepository.softDeleteByUserDomainCertId(userDomainCertId);
        int cdcUpdated = certDeploymentConfigRepository.softDeleteByUserDomainCertId(userDomainCertId);

        // Finally soft-delete the domain itself. Org-scoped update — also returns 0 if a
        // racing request already deleted it, which we treat as success (idempotent).
        int udcUpdated = udcRepository.softDeleteByIdAndOrganizationId(userDomainCertId, organizationId);

        log.info("Managed domain soft-deleted: id={}, organizationId={}, certs={}, "
                + "domainCredentialConfig={}, certDeploymentConfig={}, udc={}",
                userDomainCertId, organizationId, activeCerts.size(),
                dccUpdated, cdcUpdated, udcUpdated);
    }

    /**
     * Cascades soft-delete for a certificate that is already in REVOKED status.
     * Unlike {@link #delete}, this bypasses status validation — the cert is already
     * REVOKED so the standard DELETE validation would reject it.
     * Called from {@code CertResponseProcessor} after handling a successful revocation response.
     */
    @Transactional
    public void deleteRevoked(Long organizationId, String certificateXref) {
        certificateRepository.findByCertificateXrefAndOrganizationId(certificateXref, organizationId)
                .ifPresent(cert -> {
                    persistenceService.softDeleteAndInsertEvent(
                            certificateXref,
                            organizationId,
                            cert.getStatus(),
                            MdcIds.requestId(),
                            MdcIds.correlationId(),
                            CertificateAuditRecorder.SOURCE_EXPIRY_CLEANUP);
                    log.info("Cascading soft-delete after revocation: xref={}, organizationId={}",
                            certificateXref, organizationId);
                });
    }

    /**
     * Post-revocation cleanup that runs as soon as the agent confirms REVOCATION_SUCCESS.
     * Unlike {@link #deleteRevoked}, this does NOT soft-delete the cert or its children —
     * the cert stays visible in REVOKED status so the user can see it in list/history and
     * trigger explicit cascade-delete from the UI on their own schedule (matches the
     * cert-delete + UDC-delete endpoints that already cascade properly).
     *
     * <p>What it still does: disable the renewal_schedule row (enabled=false, not soft-delete) so
     * the renewal cron does not pick up the revoked cert. The row itself stays so cascade-delete
     * later removes it cleanly.
     */
    @Transactional
    public void finalizeRevocation(Long organizationId, String certificateXref) {
        certificateRepository.findByCertificateXrefAndOrganizationId(certificateXref, organizationId)
                .ifPresent(cert -> {
                    int disabled = renewalScheduleRepository.disableSchedule(certificateXref);
                    if (disabled > 0) {
                        log.info("Disabled renewal schedule after revocation: xref={}, organizationId={}",
                                certificateXref, organizationId);
                    }
                });
    }

    /**
     * Bulk soft-deletes all certificates (and cascades) for an entire organization.
     * Used during organization deletion — bypasses per-cert status validation.
     */
    @Transactional
    public void deleteAllCertsForOrganization(Long organizationId) {
        persistenceService.softDeleteAllByOrganizationId(organizationId);
        log.info("Bulk soft-deleted all certificates for organizationId={}", organizationId);
    }

    // ------------------------------------------------------------------ //
    //  Revoke
    // ------------------------------------------------------------------ //

    public CertificateEntity revoke(Long organizationId, String certificateXref, RevokeRequest request) {
        CertificateEntity cert = getCertForOrganization(organizationId, certificateXref);
        String status = cert.getStatus();

        if (certificateStatusValidator.isIdempotentNoOp(
                status,
                CertificateStatusValidator.CertOperation.REVOKE)) {
            log.info("[revoke] cert={} already in status={} — idempotent return",
                    certificateXref, status);
            return cert;
        }

        if (!certificateStatusValidator.isAllowedForOperation(
                status,
                CertificateStatusValidator.CertOperation.REVOKE)) {
            throw new BadRequestException(
                    "Cannot revoke certificate in state: " + status);
        }

        if (cert.getCertSecretHandle() == null || cert.getCertSecretHandle().isBlank()) {
            throw new BadRequestException(
                    "Cannot revoke certificate without certSecretHandle — the agent cannot load certificate material.");
        }

        String prevStatus    = status;
        String requestId     = MdcIds.requestId();
        String correlationId = MdcIds.correlationId();  // from frontend via MDC; null on scheduler

        Optional<CertificateEntity> persisted = persistenceService.persistRevocation(
                certificateXref, organizationId, prevStatus, request, requestId, correlationId);

        if (persisted.isEmpty()) {
            CertificateEntity latest = getCertForOrganization(organizationId, certificateXref);
            if (CertificateStatus.REVOKING.name().equals(latest.getStatus())
                    || CertificateStatus.REVOKED.name().equals(latest.getStatus())) {
                log.info("[revoke] concurrent or duplicate revoke for cert={} — returning status={}",
                        certificateXref, latest.getStatus());
                return latest;
            }
            throw new DuplicateResourceException(
                    "Certificate state changed while revoking — please retry.");
        }

        CertificateEntity revoking = persisted.get();
        String reason = request != null && request.getReason() != null && !request.getReason().isBlank()
                ? request.getReason() : ErrorCodes.DEFAULT_REVOCATION_REASON;
        Integer actorUserId = GatewayRequestContext.getUserId();

        CertRevocationCommand cmd = CertRevocationCommand.builder()
                .requestId(requestId)
                .correlationId(correlationId)
                .organizationId(organizationId.toString())
                .orgType(orgTypeResolver.resolve(organizationId))
                .certificateXref(certificateXref)
                .domain(revoking.getDomain())
                .caProvider(revoking.getCaProvider())
                .certSecretHandle(revoking.getCertSecretHandle())
                .orderId(revoking.getOrderId())
                .serialNumber(revoking.getSerialNumber())
                .caCredentialHandle(revoking.getCaCredentialHandle())
                .revocationReason(reason)
                .requestedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                .userId(actorUserId)
                .build();

        publishRevocationOrFail(cmd, certificateXref, organizationId, requestId, correlationId);
        return revoking;
    }

    private void publishRevocationOrFail(CertRevocationCommand cmd,
                                         String certificateXref,
                                         Long organizationId,
                                         String requestId,
                                         String correlationId) {
        try {
            publisher.publishRevocationCommand(cmd);
        } catch (Exception e) {
            log.error("[revoke] Failed to publish CERT_REVOCATION_COMMAND for cert={}: {}",
                    certificateXref, e.getMessage(), e);
            persistenceService.markRevocationPublishFailed(
                    certificateXref, organizationId, requestId, correlationId, e.getMessage());
            throw new ServiceUnavailableException(
                    "Failed to dispatch revocation command to cert agent. Certificate " + certificateXref +
                            " has been marked REVOCATION_FAILED — please retry.", e);
        }
    }

    // ------------------------------------------------------------------ //
    //  Dashboard
    // ------------------------------------------------------------------ //

    @Transactional(readOnly = true)
    public Map<String, Object> dashboard(Long organizationId) {
        List<Object[]> rows = certificateRepository.countByStatusForOrganization(organizationId);
        Map<String, Long> byStatus = new LinkedHashMap<>();
        long total = 0;
        for (Object[] row : rows) {
            String status = (String) row[0];
            long count    = (Long) row[1];
            byStatus.put(status, count);
            total += count;
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        long expiringIn30Days = certificateRepository.countExpiringBetween(
                organizationId, now, now.plusDays(30));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("byStatus", byStatus);
        result.put("expiringIn30Days", expiringIn30Days);
        result.put("total", total);
        return result;
    }

        @Transactional(readOnly = true)
        public CredentialRefs resolveCredentialRefsForResponse(CertificateEntity cert) {
                if (cert == null) {
                        return EMPTY_CREDENTIAL_REFS;
                }

                if (cert.getUserDomainCertId() == null) {
                        return EMPTY_CREDENTIAL_REFS;
                }

                DomainCredentialConfigEntity config = domainCredConfigRepository
                                .findByUserDomainCertId(cert.getUserDomainCertId())
                                .orElse(null);
                if (config == null) {
                        return EMPTY_CREDENTIAL_REFS;
                }

                Map<String, String> dnsConfigXref = Collections.emptyMap();
                String primaryDnsConfigXref = null;
                Map<String, String> dnsConfig = config.getDnsConfig();
                if (dnsConfig != null && !dnsConfig.isEmpty()) {
                        dnsConfigXref = new LinkedHashMap<>(dnsConfig);
                        String domain = cert.getDomain();
                        if (domain != null) {
                                primaryDnsConfigXref = SanDomainHelper.lookupRootCredXref(dnsConfig, domain);
                        }
                        if (primaryDnsConfigXref == null) {
                                // Safety fallback: config exists but primary root key is absent —
                                // return the first available credential rather than silently returning null.
                                primaryDnsConfigXref = dnsConfig.values().stream()
                                                .filter(Objects::nonNull)
                                                .findFirst()
                                                .orElse(null);
                        }
                }

                List<String> deploymentCredentialXrefs = config.getDeploymentTargets() != null
                                ? new ArrayList<>(config.getDeploymentTargets())
                                : Collections.emptyList();

                                String dnsCredentialKvPath = resolveCredentialKvPath(primaryDnsConfigXref);
                                List<String> deploymentCredentialKvPaths = deploymentCredentialXrefs.stream()
                                                                .map(this::resolveCredentialKvPath)
                                                                .filter(Objects::nonNull)
                                                                .toList();

                                return new CredentialRefs(
                                                                dnsConfigXref,
                                                                deploymentCredentialXrefs,
                                                                dnsCredentialKvPath,
                                                                deploymentCredentialKvPaths);
        }

        @Transactional(readOnly = true)
        public java.util.Map<String, CredentialRefs> resolveCredentialRefsForResponseBatch(java.util.List<CertificateEntity> certs) {
                if (certs == null || certs.isEmpty()) {
                        return java.util.Map.of();
                }

                java.util.Set<Long> udcIds = certs.stream()
                                .map(CertificateEntity::getUserDomainCertId)
                                .filter(java.util.Objects::nonNull)
                                .collect(java.util.stream.Collectors.toSet());

                java.util.Map<Long, DomainCredentialConfigEntity> configByUdcId = udcIds.isEmpty()
                                ? java.util.Map.of()
                                : domainCredConfigRepository.findByUserDomainCertIdIn(udcIds).stream()
                                        .collect(java.util.stream.Collectors.toMap(
                                                DomainCredentialConfigEntity::getUserDomainCertId,
                                                java.util.function.Function.identity(),
                                                (a, b) -> a));

                java.util.Set<String> allXrefs = new java.util.HashSet<>();
                for (DomainCredentialConfigEntity cfg : configByUdcId.values()) {
                        if (cfg.getDnsConfig() != null) {
                                cfg.getDnsConfig().values().stream().filter(Objects::nonNull).forEach(allXrefs::add);
                        }
                        if (cfg.getDeploymentTargets() != null) {
                                cfg.getDeploymentTargets().stream().filter(Objects::nonNull).forEach(allXrefs::add);
                        }
                }
                java.util.Map<String, CredentialReferenceEntity> credByXref = credentialService.getByXrefsInternal(allXrefs);

                java.util.Map<String, CredentialRefs> out = new java.util.LinkedHashMap<>(certs.size());
                for (CertificateEntity cert : certs) {
                        out.put(cert.getCertificateXref(), buildCredentialRefs(cert, configByUdcId, credByXref));
                }
                return out;
        }

        private CredentialRefs buildCredentialRefs(CertificateEntity cert,
                                                    java.util.Map<Long, DomainCredentialConfigEntity> configByUdcId,
                                                    java.util.Map<String, CredentialReferenceEntity> credByXref) {
                if (cert.getUserDomainCertId() == null) {
                        return EMPTY_CREDENTIAL_REFS;
                }
                DomainCredentialConfigEntity config = configByUdcId.get(cert.getUserDomainCertId());
                if (config == null) {
                        return EMPTY_CREDENTIAL_REFS;
                }

                Map<String, String> dnsConfigXref = Collections.emptyMap();
                String primaryDnsConfigXref = null;
                Map<String, String> dnsConfig = config.getDnsConfig();
                if (dnsConfig != null && !dnsConfig.isEmpty()) {
                        dnsConfigXref = new LinkedHashMap<>(dnsConfig);
                        String domain = cert.getDomain();
                        if (domain != null) {
                                primaryDnsConfigXref = SanDomainHelper.lookupRootCredXref(dnsConfig, domain);
                        }
                        if (primaryDnsConfigXref == null) {
                                primaryDnsConfigXref = dnsConfig.values().stream()
                                                .filter(Objects::nonNull)
                                                .findFirst()
                                                .orElse(null);
                        }
                }

                List<String> deploymentCredentialXrefs = config.getDeploymentTargets() != null
                                ? new ArrayList<>(config.getDeploymentTargets())
                                : Collections.emptyList();

                String dnsCredentialKvPath = kvPathFromMap(primaryDnsConfigXref, credByXref);
                List<String> deploymentCredentialKvPaths = deploymentCredentialXrefs.stream()
                                .map(x -> kvPathFromMap(x, credByXref))
                                .filter(Objects::nonNull)
                                .toList();

                return new CredentialRefs(dnsConfigXref, deploymentCredentialXrefs,
                                dnsCredentialKvPath, deploymentCredentialKvPaths);
        }

        private static String kvPathFromMap(String credentialXref, java.util.Map<String, CredentialReferenceEntity> credByXref) {
                if (credentialXref == null || credentialXref.isBlank()) {
                        return null;
                }
                CredentialReferenceEntity credential = credByXref.get(credentialXref);
                return credential != null ? credential.getSecretHandle() : null;
        }

        private String resolveCredentialKvPath(String credentialXref) {
                if (credentialXref == null || credentialXref.isBlank()) {
                        return null;
                }
                try {
                        CredentialReferenceEntity credential = credentialService.getByXrefInternal(credentialXref);
                        return credential != null ? credential.getSecretHandle() : null;
                } catch (ResourceNotFoundException ex) {
                        log.warn("Credential xref={} not found while building response metadata", credentialXref);
                        return null;
                }
        }

    // ------------------------------------------------------------------ //
    //  Issue helpers
    // ------------------------------------------------------------------ //

    /** Resolves and type-validates the primary DNS credential for issuance. */
    private CredentialReferenceEntity resolveDnsCredential(Long organizationId, String credXref) {
        CredentialReferenceEntity cred = resolveActiveCredential(organizationId, credXref);
        if (!"DNS".equals(cred.getType())) {
            throw new BadRequestException(
                    "Credential '" + credXref + "' must be type DNS, but found: " + cred.getType() +
                    ". Register a DNS credential for DNS challenge authorization.");
        }
        return cred;
    }

    /**
     * The CA credential for {@code caProvider}: required for DigiCert, which issues on the customer's own key, and
     * otherwise optional.
     */
    private CredentialReferenceEntity resolveCaCredential(Long organizationId, CaProvider caProvider, String credXref) {
        if (credXref == null) {
            if (caProvider == CaProvider.DIGICERT) {
                throw new BadRequestException(
                        "DigiCert issues on your own DigiCert account: add your DigiCert API key as a CA credential and send its caCredentialXref.");
            }
            return null;
        }
        CredentialReferenceEntity cred = resolveActiveCredential(organizationId, credXref);
        if (!"CA".equals(cred.getType()) || caProvider == null || !caProvider.name().equals(cred.getProvider())) {
            throw new BadRequestException("Credential '" + credXref + "' must be a " + caProvider
                    + " CA credential, but found: " + cred.getType() + " " + cred.getProvider());
        }
        return cred;
    }

    /** Returns null when {@code credXref} is null; otherwise resolves and validates ACTIVE. */
    private CredentialReferenceEntity resolveOptionalCredential(Long organizationId, String credXref) {
        return credXref != null ? resolveActiveCredential(organizationId, credXref) : null;
    }

    /**
     * Converts the already-resolved SAN entry map into CertIssuanceCommand.SanDomainEntry list.
     * Patterns are pruned within each group (wildcard-covered entries removed) before being sent
     * to the agent so the agent receives the minimal, non-redundant pattern set.
     */
    private List<CertIssuanceCommand.SanDomainEntry> buildCommandSanEntries(
            Map<CertIssuanceRequest.SanDomainEntry, CredentialReferenceEntity> sanCredMap) {
        List<CertIssuanceCommand.SanDomainEntry> entries = new ArrayList<>();
        for (Map.Entry<CertIssuanceRequest.SanDomainEntry, CredentialReferenceEntity> e
                : sanCredMap.entrySet()) {
            List<String> prunedPatterns = SanDomainHelper.pruneWithinGroup(e.getKey().getPatterns());
            if (prunedPatterns.isEmpty()) {
                continue;
            }
            entries.add(CertIssuanceCommand.SanDomainEntry.builder()
                    .dnsProvider(e.getValue().getProvider())
                    .dnsCredentialHandle(e.getValue().getSecretHandle())
                    .dnsCredentialConfigJson(e.getValue().getConfigJson())
                    .patterns(prunedPatterns)
                    .build());
        }
        return entries;
    }

    /**
     * Builds the dns_config map: { rootDomain → credentialXref }.
     *
     * <p>Keys are root domains, so that
     * all subdomains under the same root share a single credential entry. This keeps dns_config
     * compact and makes renewal reconstruction straightforward.
     *
     * <p>The primary domain's root is always the first entry. If a SAN entry maps to the same
     * root as the primary, the map entry is simply overwritten (same credential expected per the
     * design constraint that all subdomains of a root share one credential).
     */
    private Map<String, String> buildDnsConfigMap(
            String primaryDomain,
            String primaryCredXref,
            List<CertIssuanceRequest.SanDomainEntry> sanEntries) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put(SanDomainHelper.extractRootDomain(primaryDomain), primaryCredXref);
        if (sanEntries != null) {
            for (CertIssuanceRequest.SanDomainEntry sanEntry : sanEntries) {
                if (sanEntry.getPatterns() == null || sanEntry.getPatterns().isEmpty()) {
                    continue;
                }
                String rootDomain = SanDomainHelper.extractRootDomain(sanEntry.getPatterns().get(0));
                config.put(rootDomain, sanEntry.getDnsCredentialXref());
            }
        }
        return config;
    }

    private CertificateEntity buildIssuanceCert(
            UserDomainCertEntity udc, String certXref, CertIssuanceRequest request,
            CredentialReferenceEntity acme, CredentialReferenceEntity ca) {
        return CertificateEntity.builder()
                .certificateXref(certXref)
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .wildcard(Boolean.TRUE.equals(request.getWildcard()))
                .san(Boolean.TRUE.equals(request.getSan()))
                .sanDomains(extractSanDomains(request.getDomain(), Boolean.TRUE.equals(request.getWildcard()), request.getSanDomainEntries()))
                .caProvider(request.getCaProvider())
                .requestedValidityDays(request.getValidityDays())
                .status(CertificateStatus.PENDING.name())
                .certSecretHandle(null)
                .acmeAccountHandle(acme != null ? acme.getSecretHandle() : null)
                .caCredentialHandle(ca   != null ? ca.getSecretHandle()  : null)
                .keyCustody(KeyCustody.PLATFORM_HELD)
                .caAccountSource(CaAccountSource.forIssuance(request.getCaProvider(), ca != null))
                .build();
    }

    private String[] extractSanDomains(String primaryDomain, boolean wildcardPrimary,
                                       List<CertIssuanceRequest.SanDomainEntry> sanEntries) {
        return SanDomainHelper.buildCertSanDomains(primaryDomain, wildcardPrimary, sanEntries,
                CertIssuanceRequest.SanDomainEntry::getPatterns);
    }

    private RenewalScheduleEntity buildIssuanceSchedule(
            String certXref, CertIssuanceRequest request,
            CredentialReferenceEntity acme, CredentialReferenceEntity ca) {
        return RenewalScheduleEntity.builder()
                .certificateXref(certXref)
                .validTo(OffsetDateTime.now(ZoneOffset.UTC).plusYears(1))
                .renewalEligibleAt(OffsetDateTime.now(ZoneOffset.UTC).plusDays(335))
                .caProvider(request.getCaProvider())
                .acmeAccountHandle(acme != null ? acme.getSecretHandle() : null)
                .caCredentialHandle(ca   != null ? ca.getSecretHandle()  : null)
                .certSecretHandle(null)
                .enabled(false)
                .build();
    }

    private void publishIssuanceOrFail(CertIssuanceCommand command, String certXref,
                                       Long organizationId, String requestId, String correlationId) {
        try {
            publisher.publishIssuance(command);
        } catch (Exception e) {
            log.error("queue publish failed for CERT_ISSUANCE xref={}, marking FAILED: {}",
                    certXref, e.getMessage(), e);
            persistenceService.markIssuancePublishFailed(
                    certXref, organizationId, requestId, correlationId, e.getMessage());
            throw new ServiceUnavailableException(
                    "Failed to dispatch issuance command to cert agent. Cert " + certXref +
                    " has been marked FAILED — please retry.", e);
        }
    }

    // ------------------------------------------------------------------ //
    //  Renew helpers
    // ------------------------------------------------------------------ //

        private void publishRenewalOrFail(CertRenewalCommand command,
                                                                          String previousCertXref,
                                                                          String renewedCertXref,
                                      Long organizationId, String prevStatus,
                                      String requestId, String correlationId) {
        try {
            publisher.publishRenewal(command);
        } catch (Exception e) {
            if (PublishOutcome.of(e) == PublishOutcome.UNKNOWN) {
                // The command may be on its way to the agent; reverting would let a second attempt race it at the
                // CA. The attempt stays in flight and ends with its result or with the stalled-renewal recovery.
                log.error("[RENEWAL_PUBLISH_UNKNOWN] xref={} draft={}: the CERT_RENEWAL may have been sent; "
                        + "the attempt stays in flight: {}", previousCertXref, renewedCertXref, e.getMessage());
                return;
            }
            log.error("queue publish failed for CERT_RENEWAL xref={}, reverting to {}: {}",
                                        previousCertXref, prevStatus, e.getMessage(), e);
            persistenceService.markRenewalPublishFailed(
                                        previousCertXref, renewedCertXref, organizationId, prevStatus, requestId, correlationId, e.getMessage());
            throw new ServiceUnavailableException(
                                        "Failed to dispatch renewal command to cert agent. Cert " + previousCertXref +
                    " has been reverted to " + prevStatus + " — please retry.", e);
        }
    }

    // ------------------------------------------------------------------ //
    //  Deploy helpers
    // ------------------------------------------------------------------ //

    private void validateDeployPreconditions(CertificateEntity cert, String certXref) {
        String status = cert.getStatus();
        if (!certificateStatusValidator.isAllowedForOperation(
                status,
                CertificateStatusValidator.CertOperation.DEPLOY)) {
            throw new BadRequestException(
                    "Certificate '" + certXref + "' must be " + CertificateStatus.ACTIVE.name() +
                    ", " + CertificateStatus.RENEWING.name() + " or " + CertificateStatus.RENEW_SUCCESS.name() +
                    " (still valid) to deploy. Current status: " + status);
        }

        // validTo guard applies to BOTH ACTIVE and RENEWING. Status alone is not a
        // sufficient proxy for "still valid" — if CertExpiryCleanupService is delayed or
        // disabled, an ACTIVE cert can be past its validTo. Mirrors the auto-deploy
        // guard in DeploymentExecutionService.dispatchForCert.
        if (cert.getValidTo() == null
                || cert.getValidTo().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            throw new BadRequestException(
                    "Certificate '" + certXref + "' cannot be deployed — validTo=" + cert.getValidTo() +
                    " is null or in the past. Renew the certificate before deploying.");
        }
        if (cert.getCertSecretHandle() == null || cert.getCertSecretHandle().isBlank()) {
            throw new BadRequestException(
                    "Certificate '" + certXref +
                    "' has no certSecretHandle — cannot deploy without a KV source path");
        }
        if (cert.getKeyCustody() == KeyCustody.CUSTOMER_HELD
                && !AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(cert.getSpecialCertificateType())) {
            throw new BadRequestException("Certificate '" + certXref
                    + "' cannot be deployed by CertPing: the customer holds its private key.");
        }
    }

    private void validateDeployCredential(CredentialReferenceEntity cred, CertDeployRequest request) {
        if (!"DEPLOYMENT".equals(cred.getType())) {
            throw new BadRequestException(
                    "Credential '" + request.getDeploymentCredentialXref() +
                    "' must be type DEPLOYMENT, but found: " + cred.getType() +
                    ". Register a DEPLOYMENT credential for this target.");
        }
        if (!request.getTargetType().name().equals(cred.getProvider())) {
            throw new BadRequestException(
                    "Credential '" + request.getDeploymentCredentialXref() +
                    "' has provider '" + cred.getProvider() +
                    "' but targetType is '" + request.getTargetType().name() + "'. " +
                    "Use a credential whose provider matches the deployment target.");
        }
        boolean hasKubernetesExtras = request.getUseDefault() != null || request.getConfig() != null;
        if (!"KUBERNETES_SECRETS".equals(cred.getProvider()) && hasKubernetesExtras) {
            throw new BadRequestException("useDefault/config is supported only for targetType KUBERNETES_SECRETS");
        }
    }

    private String resolveManualDeploymentConfig(Long organizationId,
                                                 CertificateEntity cert,
                                                 CredentialReferenceEntity deployCred,
                                                 CertDeployRequest request) {
        // Kubernetes: legacy nsSecretMap path
        if ("KUBERNETES_SECRETS".equals(deployCred.getProvider())) {
            return kubernetesDeploymentConfigResolver.resolveOrUpsert(
                    organizationId,
                    cert.getUserDomainCertId(),
                    deployCred,
                    request.getUseDefault(),
                    request.getConfig(),
                    cert.getCertificateXref() + ":" + deployCred.getCredentialXref());
        }
        // Generic non-Kubernetes: if caller provided targets, persist them before deploying
        if (request.getTargets() != null && !request.getTargets().isNull()) {
            certDeploymentConfigService.upsertGenericTargets(
                    organizationId,
                    cert.getUserDomainCertId(),
                    deployCred,
                    request.getTargets());
        }
        return null;
    }

    // ------------------------------------------------------------------ //
    //  Common helpers
    // ------------------------------------------------------------------ //

    private CertificateEntity getCertForOrganization(Long organizationId, String xref) {
        return certificateRepository.findByCertificateXrefAndOrganizationId(xref, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Certificate '" + xref + "' not found for organization"));
    }

    private CredentialReferenceEntity resolveActiveCredential(Long organizationId, String credXref) {
        CredentialReferenceEntity cred = credentialService.getByXref(organizationId, credXref);
        if (!"ACTIVE".equals(cred.getStatus())) {
            throw new BadRequestException(
                    "credentialXref '" + credXref + "' is not ACTIVE for organization");
        }
        return cred;
    }

    /** The feature flag of a CA (e.g. {@code LETS_ENCRYPT}); the CA's issuance and renewals obey it. */
    public static String toCaFeatureKey(CaProvider provider) {
        return switch (provider) {
            case LETS_ENCRYPT -> FeatureFlags.CA_LETS_ENCRYPT;
            case DIGICERT      -> FeatureFlags.CA_DIGICERT;
            case GLOBALSIGN    -> FeatureFlags.CA_GLOBALSIGN;
        };
    }
}
