// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.credconfig.AddDeploymentTargetRequest;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.CredentialRejectedException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.audit.CredentialAuditRecorder;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class DomainCredentialConfigService {

    private static final Set<String> TARGETS_REQUIRED_PROVIDERS = Set.of(
            "AWS_ALB", "AWS_NLB",
            "AWS_API_GW_REST", "AWS_API_GW_HTTP",
            "AZURE_APP_GW", "AZURE_APP_GW_CONTAINERS",
            "AZURE_AFD");

    private final DomainCredentialConfigRepository configRepository;
    private final UserDomainCertRepository          udcRepository;
    private final CredentialReferenceService         credentialService;
    private final CertDeploymentConfigService certDeploymentConfigService;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final FeatureLifecycleLock featureLifecycleLock;
    private final CredentialReferenceRepository credentialRepository;
    /** Writes dns_credential.assigned and deployment_target.* rows in the change's transaction. */
    private final CredentialAuditRecorder credentialAudit;

    // ── Read ──────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public DomainCredentialConfigEntity getForOrganization(Long organizationId, String domain) {
        UserDomainCertEntity udc = udcRepository.findByOrganizationIdAndDomain(organizationId, domain)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No domain registration found for domain='" + domain + "' in organization"));
        return configRepository.findByUserDomainCertId(udc.getId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No credential config found for domain='" + domain + "'"));
    }

    @Transactional(readOnly = true)
    public DomainCredentialConfigEntity getById(Long configId) {
        return configRepository.findById(configId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "DomainCredentialConfig not found: " + configId));
    }

    // ── PATCH dns_config — update one domain's credential binding ─────────

    @Transactional
    public DomainCredentialConfigEntity patchDnsCredential(
            Long organizationId, String domain, String targetDomain, String credXref) {

        var cred = credentialService.getByXref(organizationId, credXref);
        if (!"DNS".equals(cred.getType())) {
            throw new CredentialRejectedException(CredentialRejectedException.TYPE_MISMATCH,
                    "credentialXref '" + credXref + "' must be type DNS, found: " + cred.getType());
        }
        if (!"ACTIVE".equals(cred.getStatus())) {
            throw new CredentialRejectedException(CredentialRejectedException.NOT_ACTIVE,
                    "credentialXref '" + credXref + "' is not ACTIVE");
        }

        DomainCredentialConfigEntity config = getForOrganization(organizationId, domain);
        String previousXref = config.getDnsConfig().put(targetDomain, credXref);
        DomainCredentialConfigEntity saved = configRepository.save(config);
        credentialAudit.dnsCredentialAssigned(cred, domain, targetDomain, previousXref);
        int rearmedSchedules = renewalScheduleRepository
                .rearmParkedFailuresByDomainCredentialConfigId(saved.getId());
        log.info("DNS credential updated: domain={}, targetDomain={}, newCred={}, rearmedSchedules={}",
                domain, targetDomain, credXref, rearmedSchedules);
        return saved;
    }

    // ── Add deployment target ─────────────────────────────────────────────

    @Transactional
    public DomainCredentialConfigEntity addDeploymentTarget(
            Long organizationId, String domain, AddDeploymentTargetRequest request) {
        // Serializes with an org admin switching deployment off (clear-first), then re-checks the flag.
        featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.CERTIFICATE_DEPLOYMENT);
        String credXref = request.getCredentialXref();

        var cred = credentialService.getByXref(organizationId, credXref);
        if (!"DEPLOYMENT".equals(cred.getType())) {
            throw new CredentialRejectedException(CredentialRejectedException.TYPE_MISMATCH,
                    "credentialXref '" + credXref + "' must be type DEPLOYMENT, found: " + cred.getType());
        }
        if (!"ACTIVE".equals(cred.getStatus())) {
            throw new CredentialRejectedException(CredentialRejectedException.NOT_ACTIVE,
                    "credentialXref '" + credXref + "' is not ACTIVE");
        }
        if (request.getConfig() != null && request.getTargets() != null) {
            throw new BadRequestException(
                    "Provide either 'config' (Kubernetes-only legacy) or 'targets' (generic) — not both");
        }

        DomainCredentialConfigEntity config = getForOrganization(organizationId, domain);
        List<String> targets = new ArrayList<>(config.getDeploymentTargets());
        boolean added = !targets.contains(credXref);
        if (added) {
            targets.add(credXref);
            config.setDeploymentTargets(targets);
            configRepository.save(config);
            log.info("Deployment target added: domain={}, credXref={}", domain, credXref);
        }

        boolean isK8s = "KUBERNETES_SECRETS".equals(cred.getProvider());

        if (request.getConfig() != null) {
            if (!isK8s) {
                throw new BadRequestException("config (kubernetes) is supported only for provider KUBERNETES_SECRETS");
            }
            boolean useDefault = Boolean.TRUE.equals(request.getConfig().getUseDefault());
            if (useDefault) {
                if (request.getConfig().getNsSecretMap() != null) {
                    log.info("Ignoring config.nsSecretMap because config.useDefault=true for domain={}, credXref={}",
                            domain, credXref);
                }
                certDeploymentConfigService.requireReconciledConfigJson(organizationId, config.getUserDomainCertId(), cred);
            } else {
                certDeploymentConfigService.validateAndUpsertKubernetesConfig(
                        organizationId,
                        config.getUserDomainCertId(),
                        cred,
                        request.getConfig().getNsSecretMap());
            }
        } else if (request.getTargets() != null) {
            if (isK8s) {
                throw new BadRequestException(
                        "Use the legacy 'config' field for KUBERNETES_SECRETS — generic 'targets' is for other providers");
            }
            certDeploymentConfigService.upsertGenericTargets(
                    organizationId, config.getUserDomainCertId(), cred, request.getTargets());
        } else if (TARGETS_REQUIRED_PROVIDERS.contains(cred.getProvider())) {
            throw new BadRequestException(
                    cred.getProvider() + " requires a 'targets' object when adding a deployment target. "
                    + "Provide the required fields (e.g. listenerArns, domainNames, listenerNames) in the request.");
        }
        // Adding a target already there with a plan replaces its plan; without one it changes nothing.
        boolean withPlan = request.getConfig() != null || request.getTargets() != null;
        if (added) {
            credentialAudit.deploymentTargetAdded(cred, domain, withPlan);
        } else if (withPlan) {
            credentialAudit.deploymentTargetUpdated(cred, domain);
        }
        return config;
    }

    // ── Edit deployment target (replace targets, preserve result) ──────────

    @Transactional
    public DomainCredentialConfigEntity editDeploymentTarget(
            Long organizationId, String domain, String credXref,
            com.certmanagement.dto.credconfig.EditDeploymentTargetRequest request) {
        // Same serialization as add: an edit must not rewrite targets a clear-first switch-off just removed.
        featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.CERTIFICATE_DEPLOYMENT);

        var cred = credentialService.getByXref(organizationId, credXref);
        if (!"DEPLOYMENT".equals(cred.getType())) {
            throw new CredentialRejectedException(CredentialRejectedException.TYPE_MISMATCH,
                    "credentialXref '" + credXref + "' must be type DEPLOYMENT, found: " + cred.getType());
        }
        if (!"ACTIVE".equals(cred.getStatus())) {
            throw new CredentialRejectedException(CredentialRejectedException.NOT_ACTIVE,
                    "credentialXref '" + credXref + "' is not ACTIVE");
        }
        if (request.getConfig() != null && request.getTargets() != null) {
            throw new BadRequestException(
                    "Provide either 'config' (Kubernetes-only legacy) or 'targets' (generic) — not both");
        }

        DomainCredentialConfigEntity config = getForOrganization(organizationId, domain);
        if (!config.getDeploymentTargets().contains(credXref)) {
            throw new BadRequestException(
                    "credentialXref '" + credXref + "' is not a deployment target for domain '" + domain + "'");
        }

        boolean isK8s = "KUBERNETES_SECRETS".equals(cred.getProvider());

        if (isK8s) {
            if (request.getConfig() == null || Boolean.TRUE.equals(request.getConfig().getUseDefault())) {
                throw new BadRequestException(
                        "Editing a KUBERNETES_SECRETS target requires config.nsSecretMap (useDefault is invalid for edit)");
            }
            certDeploymentConfigService.validateAndUpsertKubernetesConfig(
                    organizationId,
                    config.getUserDomainCertId(),
                    cred,
                    request.getConfig().getNsSecretMap());
        } else {
            if (request.getTargets() == null) {
                throw new BadRequestException("targets is required when editing a non-Kubernetes deployment target");
            }
            certDeploymentConfigService.upsertGenericTargets(
                    organizationId, config.getUserDomainCertId(), cred, request.getTargets());
        }

        credentialAudit.deploymentTargetUpdated(cred, domain);
        log.info("Deployment target edited: domain={}, credXref={}", domain, credXref);
        return config;
    }

    // ── Remove deployment target ──────────────────────────────────────────

    @Transactional
    public DomainCredentialConfigEntity removeDeploymentTarget(
            Long organizationId, String domain, String credXref) {

        DomainCredentialConfigEntity config = getForOrganization(organizationId, domain);
        List<String> targets = new ArrayList<>(config.getDeploymentTargets());
        if (targets.remove(credXref)) {
            config.setDeploymentTargets(targets);
            configRepository.save(config);
            // One lookup, only when a target was removed: the row names the credential, which may since be deleted.
            credentialAudit.deploymentTargetRemoved(organizationId, credXref,
                    credentialRepository.findByCredentialXrefAndOrganizationId(credXref, organizationId).orElse(null),
                    domain);
            log.info("Deployment target removed: domain={}, credXref={}", domain, credXref);
        }
        return config;
    }
}
