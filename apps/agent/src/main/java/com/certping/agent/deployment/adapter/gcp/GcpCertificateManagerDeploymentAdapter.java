// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.cloud.gcp.GcpAuthMode;
import com.certping.agent.deployment.cloud.gcp.GcpAuthScope;
import com.certping.agent.deployment.cloud.gcp.GcpAuthSecret;
import com.certping.agent.deployment.cloud.gcp.GcpCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import com.google.auth.oauth2.GoogleCredentials;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * GCP Certificate Manager deployment adapter.
 *
 * <p>Flow:
 * <ol>
 *   <li>Upload (or in-place update) a self-managed Certificate resource — get its full name.</li>
 *   <li>If {@code scope.certificateMap} is configured: derive the hostname set from the cert's
 *       CN+SANs, list existing {@code CertificateMapEntry} resources on the map, and for each
 *       hostname either update the matching entry's {@code certificates[]} or create a new
 *       entry binding hostname → cert resource.</li>
 *   <li>If the map is empty/blank: stop after the cert upload (operator binds via target proxy
 *       SSL config out-of-band).</li>
 *   <li>Best-effort delete of any superseded prior cert resource after entries repointed.</li>
 * </ol>
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.GCP_CERT_MANAGER)
@RequiredArgsConstructor
public class GcpCertificateManagerDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "GCP Certificate Manager";

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final GcpCertificateManagerService certificateManagerService;
    private final GcpCertificateMapDeployer certificateMapDeployer;
    private final GcpCloudCredentialResolver credentialResolver;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        GcpCertManagerScope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);
        GcpCertManagerTargets targets = parseTargets(message.getTargetsJson());

        String projectId = scope.projectId().trim();
        String location = scope.location().trim();
        String certificateMap = scope.certificateMap() == null ? "" : scope.certificateMap().trim();
        String operatorCertName = targets.certificateName() == null ? "" : targets.certificateName().trim();
        String autoBaseName = GcpNameUtils.deriveBaseName(
                message.getDomain(), message.getCertificateXref());

        GcpAuthMode authMode = GcpScopeSupport.parseAuthMode(scope.authMode(), CTX);
        GcpAuthScope authScope = GcpScopeSupport.toAuthScope(projectId, location, scope.impersonateServiceAccount());

        GcpAuthSecret kvSecret = GcpAuthSecret.empty();
        if (message.getDeploymentCredHandle() != null && !message.getDeploymentCredHandle().isBlank()) {
            String credRaw = secretStore.read(message.getDeploymentCredHandle());
            kvSecret = GcpScopeSupport.parseKvSecret(objectMapper, credRaw, CTX);
        }

        GoogleCredentials credentials = credentialResolver.resolve(authMode, authScope, kvSecret, CTX);

        // Resolve effective cert id with targets-first precedence (operator's current intent wins).
        // In-place update is attempted ONLY when targets is blank (renewal) or targets matches
        // the prior resource's id (renewal with explicit pin). If targets names a different id
        // than the prior resource, that's a rename — create new and mark prior for cleanup.
        String priorCertResourceName = GcpDeploymentSupport.readPriorCertResourceName(
                objectMapper, message.getConfigJson(), "certificateResourceName");
        String priorCertId = extractCertIdFromResourceName(priorCertResourceName);
        String operatorDesiredId = operatorCertName.isBlank()
                ? null : GcpNameUtils.toResourceId(operatorCertName, "certping");

        String certResourceName;
        String priorToCleanup = null;

        boolean inPlaceUpdateEligible =
                priorCertResourceName != null
                && (operatorDesiredId == null || operatorDesiredId.equals(priorCertId));

        if (inPlaceUpdateEligible
                && certificateManagerService.updateCertificate(priorCertResourceName, bundle, credentials)) {
            log.info("{} in-place update succeeded: certResource={}, xref={}",
                    CTX, priorCertResourceName, message.getCertificateXref());
            certResourceName = priorCertResourceName;
        } else {
            // Create new resource. Id resolution:
            //   - operator-supplied targets.certificateName on first deploy or matching prior →
            //     use it literally (stable, Azure-style)
            //   - operator-supplied that differs from prior → rename: use literal (the OLD resource
            //     becomes orphan; cleanup attempted below)
            //   - SAN-change fallback (no operator name, prior exists) → versioned id to avoid
            //     colliding with the still-existing prior
            //   - first deploy with no operator name → versioned auto-derived id
            String certificateId;
            if (operatorDesiredId != null && (priorCertResourceName == null || !operatorDesiredId.equals(priorCertId))) {
                certificateId = operatorDesiredId;
            } else {
                String base = operatorCertName.isBlank() ? autoBaseName : operatorCertName;
                certificateId = GcpNameUtils.versionedId(base);
            }
            log.info("{} create new: projectId={}, location={}, certId={}, xref={}",
                    CTX, projectId, location, certificateId, message.getCertificateXref());
            certResourceName = certificateManagerService.createCertificate(
                    projectId, location, certificateId, bundle, credentials);
            if (priorCertResourceName != null) {
                priorToCleanup = priorCertResourceName;
            }
        }

        // Bind to map entries (only if a map is configured).
        List<ObjectNode> appliedEntries = new ArrayList<>();
        if (!certificateMap.isBlank()) {
            for (GcpCertificateMapDeployer.AppliedEntry applied : certificateMapDeployer.bindHostnames(
                    projectId, location, certificateMap, certResourceName, bundle, credentials)) {
                ObjectNode entryNode = objectMapper.createObjectNode();
                entryNode.put("hostname", applied.hostname());
                entryNode.put("certificateMapEntry", applied.certificateMapEntry());
                entryNode.put("action", applied.action());
                appliedEntries.add(entryNode);
            }
        }

        // Cleanup the superseded resource AFTER all entries are repointed (best-effort).
        if (priorToCleanup != null) {
            certificateManagerService.deleteCertificate(priorToCleanup, credentials);
        }

        log.info("{} deployment complete: project={}, map={}, entriesApplied={}, xref={}",
                CTX, projectId, certificateMap.isBlank() ? "(none)" : certificateMap,
                appliedEntries.size(), message.getCertificateXref());

        ObjectNode resultNode = objectMapper.createObjectNode();
        resultNode.put("certificateResourceName", certResourceName);
        if (!certificateMap.isBlank()) {
            resultNode.put("certificateMap", certificateMap);
            ArrayNode arr = resultNode.putArray("appliedEntries");
            appliedEntries.forEach(arr::add);
        }

        String configJson;
        try {
            configJson = objectMapper.writeValueAsString(resultNode);
        } catch (Exception e) {
            configJson = "{\"certificateResourceName\":\"" + certResourceName + "\"}";
        }

        return DeploymentResult.of(certResourceName, configJson);
    }

    void validateScope(GcpCertManagerScope scope) {
        requireField(scope.projectId(), "scope.projectId");
        requireField(scope.location(), "scope.location");
        // certificateMap is optional — when blank, no map binding happens.
    }

    private GcpCertManagerScope parseScope(String scopeJson) {
        if (scopeJson == null || scopeJson.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScopeJson is required");
        }
        try {
            return objectMapper.readValue(scopeJson, GcpCertManagerScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " failed to parse credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private GcpCertManagerTargets parseTargets(String targetsJson) {
        if (targetsJson == null || targetsJson.isBlank()) {
            return new GcpCertManagerTargets(null);
        }
        try {
            return objectMapper.readValue(targetsJson, GcpCertManagerTargets.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    CTX + " failed to parse targetsJson: " + e.getMessage(), e);
        }
    }

    /**
     * Extract the trailing id from a GCP cert resource name like
     * {@code projects/{p}/locations/{l}/certificates/{id}}. Returns {@code null} if input is null
     * or doesn't look like a resource name.
     */
    private static String extractCertIdFromResourceName(String fullResourceName) {
        if (fullResourceName == null || fullResourceName.isBlank()) return null;
        int idx = fullResourceName.lastIndexOf('/');
        if (idx < 0 || idx == fullResourceName.length() - 1) return null;
        return fullResourceName.substring(idx + 1);
    }

    private static String requireField(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + fieldName);
        }
        return value.trim();
    }
}
