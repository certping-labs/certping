// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.MissingDnsCredentialConfigurationException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertConversionService {

    private final CertificateRepository certificateRepository;
    private final DomainCredentialConfigRepository domainCredentialConfigRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final CertManualIssuanceStateRepository manualIssuanceStateRepository;
    private final CertificateEventRepository certificateEventRepository;
    private final CredentialReferenceService credentialReferenceService;
    private final CertIssuanceService certIssuanceService;
    private final CertificateStatusValidator certificateStatusValidator;
    private final com.certmanagement.service.deployment.CertDeploymentConfigService certDeploymentConfigService;
    private final KubernetesDeploymentConfigResolver kubernetesDeploymentConfigResolver;
    private final ObjectMapper objectMapper;
    private final CertificateFeatureLocks certificateFeatureLocks;
    /** Writes the conversion's audit row in this transaction. */
    private final com.certmanagement.service.audit.CertificateAuditRecorder certificateAudit;

    /** The 423 a conversion with deployment targets gets while CERTIFICATE_DEPLOYMENT is off. */
    static final String DEPLOYMENT_OFF_MESSAGE = "Automatic deployment is turned off for your organization. "
            + "Convert the certificate without deployment targets, or ask an admin to turn deployment back on.";

    /**
     * Converts a certificate to automated renewal (and deployment, with targets).
     *
     * <p>Clear-first: before any row lock or write, takes the CERTIFICATE_RENEWAL, CA and (with targets)
     * CERTIFICATE_DEPLOYMENT locks and re-checks them past the cache, so a conversion can never turn
     * automation back on after an org admin's switch-off found nothing in use. The certificate is read
     * first, without a row lock, only to learn its CA.
     *
     * @throws com.certmanagement.exception.FeatureDisabledException (423) when renewal, the CA or,
     *         with targets, deployment is off
     */
    @Transactional
    public Map<String, Object> convertToAutomated(Long organizationId, String certXref, ConvertToAutomatedRequest request) {
        CertificateEntity cert = certificateRepository
                .findByCertificateXrefAndOrganizationId(certXref, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Certificate '" + certXref + "' not found for organization"));
        // CERTIFICATE_ISSUANCE is locked up front too (in sorted order) because a terminal certificate is
        // re-issued below, and that issuance takes its lock; it requires it then.
        certificateFeatureLocks.lockAndRequire(organizationId, conversionFeatureKeys(cert, request),
                List.of(FeatureFlags.CERTIFICATE_ISSUANCE), DEPLOYMENT_OFF_MESSAGE);

        ConvertToAutomatedRequest.ActivationMode activationMode =
                request.getActivationMode() != null
                        ? request.getActivationMode()
                        : ConvertToAutomatedRequest.ActivationMode.NEXT_RENEWAL;
        ConvertToAutomatedRequest.InFlightPolicy inFlightPolicy =
                request.getInFlightPolicy() != null
                        ? request.getInFlightPolicy()
                        : ConvertToAutomatedRequest.InFlightPolicy.WAIT;

        String primaryDomain = cert.getDomain();
        if (primaryDomain == null || primaryDomain.isBlank()) {
            throw new BadRequestException("Certificate '" + certXref + "' has no resolvable primary domain");
        }

        Map<String, String> dnsConfig = buildValidatedDnsConfig(organizationId, primaryDomain, request.getDnsMappings());
        if (Boolean.TRUE.equals(cert.getSan())) {
            sanNamesByCredential(cert, primaryDomain, dnsConfig);
        }
        List<String> deploymentTargets = buildValidatedDeploymentTargets(organizationId, request.getDeploymentTargets());
        List<String> targetsBefore = new ArrayList<>();
        DomainCredentialConfigEntity config = upsertCredentialConfig(cert.getUserDomainCertId(), dnsConfig,
                deploymentTargets, targetsBefore);
        certificateAudit.deploymentTargetsReplaced(organizationId, primaryDomain, targetsBefore, deploymentTargets);

        // Apply inline per-target configs (e.g. Azure KV certificateName, K8s nsSecretMap)
        if (request.getDeploymentTargetConfigs() != null && !deploymentTargets.isEmpty()) {
            for (CertIssuanceRequest.DeploymentTargetConfigEntry entry : request.getDeploymentTargetConfigs()) {
                String credXref = entry.getDeploymentCredentialXref();
                if (credXref == null || credXref.isBlank() || !deploymentTargets.contains(credXref)) continue;
                CredentialReferenceEntity deployCred = credentialReferenceService.getByXref(organizationId, credXref);
                if ("KUBERNETES_SECRETS".equals(deployCred.getProvider()) && entry.getConfig() != null) {
                    kubernetesDeploymentConfigResolver.resolveOrUpsert(
                            organizationId, cert.getUserDomainCertId(), deployCred,
                            entry.getConfig().getUseDefault(), entry.getConfig().getNsSecretMap(),
                            primaryDomain + ":" + credXref);
                } else if (entry.getTargets() != null && !entry.getTargets().isNull()) {
                    certDeploymentConfigService.upsertGenericTargets(
                            organizationId, cert.getUserDomainCertId(), deployCred, entry.getTargets());
                }
            }
        }

        insertEvent(
                cert,
                CertEventType.CONVERSION_REQUESTED.name(),
                cert.getStatus(),
                cert.getStatus(),
                Map.of(
                        "activationMode", activationMode.name(),
                        "inFlightPolicy", inFlightPolicy.name(),
                        "dnsDomainCount", dnsConfig.size(),
                        "deploymentTargetCount", deploymentTargets.size()));

        String status = cert.getStatus();
        certificateStatusValidator.validateForOperation(
            cert,
            certXref,
            CertificateStatusValidator.CertOperation.CONVERT_TO_AUTOMATED);
        String plannedAction;
        String effectiveWhen;
        String triggeredCertificateXref = null;

        if (certificateStatusValidator.isConversionStatusActiveOrExpired(status)) {
            ensureOrRepairSchedule(cert, config);
            if (activationMode == ConvertToAutomatedRequest.ActivationMode.IMMEDIATE) {
                certIssuanceService.renew(organizationId, certXref, null);
                plannedAction = "CONFIG_UPDATED_AND_RENEWAL_TRIGGERED";
                effectiveWhen = "immediate";
                triggeredCertificateXref = certXref;
                insertEvent(cert, CertEventType.CONVERSION_TRIGGERED_RENEWAL.name(), status, status,
                        Map.of("mode", activationMode.name()));
            } else {
                plannedAction = "CONFIG_UPDATED_NEXT_RENEWAL";
                effectiveWhen = "next_renewal_window";
                insertEvent(cert, CertEventType.CONVERSION_DEFERRED.name(), status, status,
                        Map.of("reason", "activation_mode_next_renewal"));
            }
        } else if (certificateStatusValidator.isConversionStatusTerminalReissue(status)) {
            CertificateEntity issued = certIssuanceService.issue(organizationId,
                    toAutomatedIssuanceRequest(cert, primaryDomain, dnsConfig, deploymentTargets));
            plannedAction = "CONFIG_UPDATED_AND_ISSUANCE_TRIGGERED";
            effectiveWhen = "immediate";
            triggeredCertificateXref = issued.getCertificateXref();
            insertEvent(cert, CertEventType.CONVERSION_TRIGGERED_ISSUANCE.name(), status, status,
                    Map.of("triggeredCertificateXref", issued.getCertificateXref()));
        } else if (certificateStatusValidator.isConversionStatusInProgressAutomated(status)) {
            plannedAction = "CONFIG_UPDATED_DEFERRED_IN_PROGRESS";
            effectiveWhen = "after_in_flight_operation";
            insertEvent(cert, CertEventType.CONVERSION_DEFERRED.name(), status, status,
                    Map.of("reason", "certificate_status_in_progress"));
        } else if (certificateStatusValidator.isConversionStatusManualInFlight(status)) {
            if (inFlightPolicy == ConvertToAutomatedRequest.InFlightPolicy.WAIT) {
                plannedAction = "CONFIG_UPDATED_WAITING_MANUAL_COMPLETION";
                effectiveWhen = "after_manual_flow_completion";
                insertEvent(cert, CertEventType.CONVERSION_DEFERRED.name(), status, status,
                        Map.of("reason", "manual_flow_in_progress_wait_policy"));
            } else {
                cert.setStatus(CertificateStatus.CANCELLED_MANUAL.name());
                cert.setLastErrorCode(null);
                cert.setLastErrorMessage(null);
                cert.setLastErrorAt(null);
                certificateRepository.save(cert);
                manualIssuanceStateRepository.deleteByCertXref(certXref);

                insertEvent(cert, CertEventType.CONVERSION_CANCELLED_MANUAL.name(), status,
                        CertificateStatus.CANCELLED_MANUAL.name(),
                        Map.of("reason", "in_flight_policy_cancel_and_reissue"));

                CertificateEntity issued = certIssuanceService.issue(organizationId,
                        toAutomatedIssuanceRequest(cert, primaryDomain, dnsConfig, deploymentTargets));
                plannedAction = "MANUAL_CANCELLED_AND_ISSUANCE_TRIGGERED";
                effectiveWhen = "immediate";
                triggeredCertificateXref = issued.getCertificateXref();
                insertEvent(cert, CertEventType.CONVERSION_TRIGGERED_ISSUANCE.name(),
                        CertificateStatus.CANCELLED_MANUAL.name(),
                        CertificateStatus.CANCELLED_MANUAL.name(),
                        Map.of("triggeredCertificateXref", issued.getCertificateXref()));
            }
        } else {
            throw new BadRequestException(
                    "Certificate '" + certXref + "' cannot be converted in current status: " + status);
        }

        certificateAudit.convertedToAutomated(cert, activationMode.name(), plannedAction, deploymentTargets.size());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("certificateXref", certXref);
        response.put("userDomainCertId", cert.getUserDomainCertId());
        response.put("domain", primaryDomain);
        response.put("currentStatus", status);
        response.put("activationMode", activationMode.name());
        response.put("inFlightPolicy", inFlightPolicy.name());
        response.put("plannedAction", plannedAction);
        response.put("effectiveWhen", effectiveWhen);
        if (triggeredCertificateXref != null) {
            response.put("triggeredCertificateXref", triggeredCertificateXref);
        }
        response.put("convertedAt", OffsetDateTime.now(ZoneOffset.UTC).toString());
        return response;
    }

    /** What a conversion puts in use: automatic renewal on the cert's CA, and deployment with targets. */
    private static List<String> conversionFeatureKeys(CertificateEntity cert, ConvertToAutomatedRequest request) {
        List<String> featureKeys = new ArrayList<>(List.of(FeatureFlags.CERTIFICATE_RENEWAL));
        if (cert.getCaProvider() != null) {
            featureKeys.add(CertIssuanceService.toCaFeatureKey(cert.getCaProvider()));
        }
        if (request.getDeploymentTargets() != null && !request.getDeploymentTargets().isEmpty()) {
            featureKeys.add(FeatureFlags.CERTIFICATE_DEPLOYMENT);
        }
        return featureKeys;
    }

    private Map<String, String> buildValidatedDnsConfig(
            Long organizationId,
            String primaryDomain,
            List<ConvertToAutomatedRequest.DnsCredentialMapping> mappings) {
        if (mappings == null || mappings.isEmpty()) {
            throw new BadRequestException("dnsMappings must contain at least one domain mapping");
        }

        Map<String, String> config = new LinkedHashMap<>();
        Set<String> seenDomains = new LinkedHashSet<>();

        for (ConvertToAutomatedRequest.DnsCredentialMapping mapping : mappings) {
            if (mapping == null || mapping.getDomain() == null || mapping.getCredentialXref() == null) {
                throw new BadRequestException("Each dnsMappings entry requires domain and credentialXref");
            }

            String normalizedDomain = normalizeDomain(mapping.getDomain());
            if (!seenDomains.add(normalizedDomain)) {
                throw new BadRequestException("Duplicate domain in dnsMappings: " + mapping.getDomain());
            }

            CredentialReferenceEntity credential = credentialReferenceService
                    .getByXref(organizationId, mapping.getCredentialXref());
            if (!"DNS".equals(credential.getType())) {
                throw new BadRequestException(
                        "dnsMappings credentialXref '" + mapping.getCredentialXref() + "' must be type DNS");
            }
            if (!"ACTIVE".equals(credential.getStatus())) {
                throw new BadRequestException(
                        "dnsMappings credentialXref '" + mapping.getCredentialXref() + "' is not ACTIVE");
            }

            config.put(normalizedDomain, mapping.getCredentialXref());
        }

        // dns_config uses root-domain keys — callers must provide the root,
        // not the full subdomain.
        String primaryRoot = SanDomainHelper.extractRootDomain(primaryDomain);
        if (!config.containsKey(primaryRoot)) {
            throw new BadRequestException(
                    "dnsMappings must include a mapping for primary domain '" + primaryDomain
                    + "'. Provide root domain '" + primaryRoot + "'.");
        }

        return config;
    }

    private List<String> buildValidatedDeploymentTargets(Long organizationId, List<String> deploymentTargets) {
        List<String> targets = deploymentTargets != null ? deploymentTargets : List.of();
        List<String> dedupedTargets = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        for (String credXref : targets) {
            if (credXref == null || credXref.isBlank()) {
                throw new BadRequestException("deploymentTargets cannot contain blank values");
            }
            if (!seen.add(credXref)) {
                continue;
            }
            CredentialReferenceEntity credential = credentialReferenceService.getByXref(organizationId, credXref);
            if (!"DEPLOYMENT".equals(credential.getType())) {
                throw new BadRequestException(
                        "deploymentTargets credentialXref '" + credXref + "' must be type DEPLOYMENT");
            }
            if (!"ACTIVE".equals(credential.getStatus())) {
                throw new BadRequestException(
                        "deploymentTargets credentialXref '" + credXref + "' is not ACTIVE");
            }
            dedupedTargets.add(credXref);
        }

        return dedupedTargets;
    }

    /** Replaces the domain's configuration; the deployment targets it had are added to {@code targetsBefore}. */
    private DomainCredentialConfigEntity upsertCredentialConfig(
            Long userDomainCertId,
            Map<String, String> dnsConfig,
            List<String> deploymentTargets,
            List<String> targetsBefore) {
        DomainCredentialConfigEntity config = domainCredentialConfigRepository
                .findByUserDomainCertId(userDomainCertId)
                .orElseGet(() -> DomainCredentialConfigEntity.builder()
                        .userDomainCertId(userDomainCertId)
                        .build());
        if (config.getDeploymentTargets() != null) {
            targetsBefore.addAll(config.getDeploymentTargets());
        }

        config.setDnsConfig(new LinkedHashMap<>(dnsConfig));
        config.setDeploymentTargets(new ArrayList<>(deploymentTargets));
        return domainCredentialConfigRepository.save(config);
    }

    private void ensureOrRepairSchedule(CertificateEntity cert, DomainCredentialConfigEntity config) {
        renewalScheduleRepository.findByCertificateXref(cert.getCertificateXref())
                .ifPresentOrElse(existing -> {
                    existing.setDomainCredentialConfigId(config.getId());
                    existing.setEnabled(true);
                    existing.setCaProvider(cert.getCaProvider());
                    if (cert.getAcmeAccountHandle() != null) {
                        existing.setAcmeAccountHandle(cert.getAcmeAccountHandle());
                    }
                    if (cert.getCaCredentialHandle() != null) {
                        existing.setCaCredentialHandle(cert.getCaCredentialHandle());
                    }
                    if (cert.getOrderId() != null) {
                        existing.setOrderId(cert.getOrderId());
                    }
                    if (cert.getCertSecretHandle() != null) {
                        existing.setCertSecretHandle(cert.getCertSecretHandle());
                    }
                    if (cert.getValidTo() != null) {
                        existing.setValidTo(cert.getValidTo());
                        existing.setRenewalEligibleAt(RenewalTiming.eligibleAt(cert.getValidFrom(), cert.getValidTo(), existing.getRenewalWindowDays()));
                    }
                    renewalScheduleRepository.save(existing);
                }, () -> {
                    if (cert.getValidTo() == null) {
                        throw new BadRequestException(
                                "Cannot create renewal schedule for cert='" + cert.getCertificateXref()
                                        + "' without validTo");
                    }
                    if (cert.getCertSecretHandle() == null || cert.getCertSecretHandle().isBlank()) {
                        throw new BadRequestException(
                                "Cannot create renewal schedule for cert='" + cert.getCertificateXref()
                                        + "' without certSecretHandle");
                    }
                    RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                            .certificateXref(cert.getCertificateXref())
                            .domainCredentialConfigId(config.getId())
                            .caProvider(cert.getCaProvider())
                            .acmeAccountHandle(cert.getAcmeAccountHandle())
                            .caCredentialHandle(cert.getCaCredentialHandle())
                            .orderId(cert.getOrderId())
                            .certSecretHandle(cert.getCertSecretHandle())
                            .validTo(cert.getValidTo())
                            .renewalEligibleAt(RenewalTiming.eligibleAt(cert.getValidFrom(), cert.getValidTo(), RenewalTiming.DEFAULT_WINDOW_DAYS))
                            .renewalWindowDays(30)
                            .enabled(true)
                            .build();
                    renewalScheduleRepository.save(schedule);
                });
    }

    private CertIssuanceRequest toAutomatedIssuanceRequest(
            CertificateEntity cert,
            String primaryDomain,
            Map<String, String> dnsConfig,
            List<String> deploymentTargets) {
        CertIssuanceRequest issuanceRequest = new CertIssuanceRequest();
        issuanceRequest.setDomain(primaryDomain);
        issuanceRequest.setWildcard(Boolean.TRUE.equals(cert.getWildcard()));
        issuanceRequest.setSan(Boolean.TRUE.equals(cert.getSan()));
        issuanceRequest.setCaProvider(cert.getCaProvider());
        issuanceRequest.setDnsCredentialXref(SanDomainHelper.lookupRootCredXref(dnsConfig, primaryDomain));
        issuanceRequest.setDeploymentTargets(new ArrayList<>(deploymentTargets));

        if (!Boolean.TRUE.equals(cert.getSan())) {
            if (dnsConfig.size() > 1) {
                throw new BadRequestException(
                        "dnsMappings contains SAN domains but certificate is non-SAN for xref='"
                                + cert.getCertificateXref() + "'");
            }
            return issuanceRequest;
        }

        SanDomainHelper.SanNamesByConfigKey names = sanNamesByCredential(cert, primaryDomain, dnsConfig);
        List<CertIssuanceRequest.SanDomainEntry> sanEntries = new ArrayList<>();
        names.byConfigKey().forEach((key, patterns) -> sanEntries.add(sanEntry(dnsConfig.get(key), patterns)));
        if (!names.primaryRootNames().isEmpty()) {
            sanEntries.add(sanEntry(issuanceRequest.getDnsCredentialXref(), names.primaryRootNames()));
        }

        issuanceRequest.setSanDomainEntries(sanEntries);
        return issuanceRequest;
    }

    /**
     * The certificate's SAN names by the mapping that covers each; checked on every conversion path, so a
     * conversion never saves mappings that leave a name without a credential for its next renewal.
     *
     * @throws BadRequestException when a name has no mapping
     */
    private static SanDomainHelper.SanNamesByConfigKey sanNamesByCredential(
            CertificateEntity cert, String primaryDomain, Map<String, String> dnsConfig) {
        try {
            return SanDomainHelper.sanNamesByConfigKey(primaryDomain, cert.getSanDomains(), dnsConfig);
        } catch (MissingDnsCredentialConfigurationException e) {
            throw new BadRequestException("dnsMappings has no credential for a name on certificate xref='"
                    + cert.getCertificateXref() + "': " + e.getMessage());
        }
    }

    private static CertIssuanceRequest.SanDomainEntry sanEntry(String credentialXref, List<String> patterns) {
        CertIssuanceRequest.SanDomainEntry entry = new CertIssuanceRequest.SanDomainEntry();
        entry.setDnsCredentialXref(credentialXref);
        entry.setPatterns(new ArrayList<>(patterns));
        return entry;
    }

    private void insertEvent(
            CertificateEntity cert,
            String eventType,
            String fromStatus,
            String toStatus,
            Map<String, Object> details) {
        try {
            CertificateEventEntity event = CertificateEventEntity.builder()
                    .certificateXref(cert.getCertificateXref())
                    .organizationId(cert.getOrganizationId())
                    .eventType(eventType)
                    .fromStatus(fromStatus)
                    .toStatus(toStatus)
                    .source(EventSource.CERT_MANAGER.value())
                    .details(objectMapper.writeValueAsString(details))
                    .build();
            certificateEventRepository.save(event);
        } catch (Exception e) {
            log.error("Failed to insert conversion event {} for xref={}: {}",
                    eventType, cert.getCertificateXref(), e.getMessage(), e);
        }
    }

    private String normalizeDomain(String domain) {
        return domain.trim().toLowerCase();
    }
}
