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
import com.google.auth.oauth2.GoogleCredentials;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * GCP target SSL proxy deployment for Proxy NLB.
 *
 * <p>One credential = one SSL proxy. The proxy name and certificate base name live in
 * the credential scope. Per-cert targets are empty ({@code {}}).
 *
 * <p><b>Why this adapter uses native {@code compute.sslCertificates}, not Certificate Manager</b>:
 * Target SSL Proxies (the resource Proxy NLB uses) only accept native compute SslCertificate URLs
 * on their {@code sslCertificates[]} field — they reject Certificate Manager URLs (with or without
 * the {@code //certificatemanager.googleapis.com/} prefix) as malformed. Target HTTPS Proxies
 * accept both shapes; Target SSL Proxies accept only this one. So Proxy NLB has its own create /
 * delete path via {@link GcpComputeSslCertificateService}.
 *
 * <p><b>No in-place update</b>: Compute {@code SslCertificate} is immutable. Every deploy creates a
 * new versioned resource, swaps it onto the Target SSL Proxy, and deletes the prior resource. The
 * inverse of {@link GcpAlbDeploymentAdapter}'s in-place try-then-fallback path — which works for
 * Certificate Manager certs but isn't available here.
 *
 * <p>When the proxy serves from a certificate map, GCP ignores its {@code sslCertificates}, so the
 * certificate is deployed into that map instead ({@link GcpCertificateMapDeployer}).
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.GCP_PROXY_NLB)
@RequiredArgsConstructor
public class GcpProxyNlbDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "GCP Proxy NLB";

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final GcpComputeSslCertificateService computeSslCertificateService;
    private final GcpTargetProxyService targetProxyService;
    private final GcpCertificateMapDeployer certificateMapDeployer;
    private final GcpCloudCredentialResolver gcpCredentialResolver;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        GcpProxyScope scope = parseScope(message.getCredentialScopeJson());
        validateScope(scope);

        GcpAuthMode authMode = GcpScopeSupport.parseAuthMode(scope.authMode(), CTX);
        String projectId = scope.projectId().trim();
        String location = scope.location().trim();
        String targetSslProxy = scope.targetSslProxy().trim();
        String certificateBaseName = GcpNameUtils.deriveBaseName(
                message.getDomain(), message.getCertificateXref());

        GcpAuthSecret kv = readKvSecret(message);
        GcpAuthScope authScope = GcpScopeSupport.toAuthScope(
                projectId, location, scope.impersonateServiceAccount());
        GoogleCredentials credentials = gcpCredentialResolver.resolve(authMode, authScope, kv, CTX);

        // Always create-new — Compute SslCertificate is immutable, so there is no in-place update.
        // The prior resource (if any) is cleaned up below after the proxy's cert list no longer
        // references it. {@link GcpDeploymentSupport#readPriorCertResourceName} is reused here
        // because the configJson key is the same ("certificateName") across all GCP adapters even
        // though the URL shape differs between Certificate Manager and Compute SslCertificate.
        String priorCertResourceName = GcpDeploymentSupport.readPriorCertResourceName(
                objectMapper, message.getConfigJson(), "certificateName");

        // Read the proxy first so a proxy the agent cannot deploy to fails before a cert is created.
        GcpTargetProxyConfig config = new GcpTargetProxyConfig(projectId, location, targetSslProxy);
        GcpTargetProxyState proxy = targetProxyService.fetchSslProxy(config, credentials);
        String targetResourceId = "gcp://target-ssl-proxy/" + targetSslProxy;
        if (proxy.usesCertificateMap()) {
            // GCP ignores sslCertificates while a map is attached, so the map is what serves.
            GcpCertificateMapDeployer.MapDeployment deployment = certificateMapDeployer.deployToProxyMap(
                    proxy.certificateMap(), certificateBaseName, priorCertResourceName, bundle, credentials);
            log.info("{} deployment complete through certificate map: project={}, proxy={}, map={}, xref={}",
                    CTX, projectId, targetSslProxy, deployment.certificateMap(), message.getCertificateXref());
            return DeploymentResult.of(targetResourceId,
                    GcpDeploymentSupport.proxyMapResultConfigJson(objectMapper, deployment));
        }
        if (GcpTargetProxyService.looksLikeCertManagerResourceName(priorCertResourceName)) {
            // The prior deploy went through a map since detached; compute pruning must not touch it.
            priorCertResourceName = null;
        }

        String certificateId = GcpNameUtils.versionedId(certificateBaseName);
        log.info("{} create new: project={}, sslProxy={}, certId={}, xref={}",
                CTX, projectId, targetSslProxy, certificateId, message.getCertificateXref());
        String certResourceName = computeSslCertificateService.createSslCertificate(
                projectId, location, certificateId, bundle, credentials);

        GcpDeploymentSupport.CertificatePrune prune;
        try {
            // Re-read after the create so the read-modify-write window does not span the create's
            // operation; setSslCertificates has no fingerprint and other deploys may share the proxy.
            List<String> existing = targetProxyService.fetchSslProxy(config, credentials).sslCertificates();
            prune = GcpDeploymentSupport.mergeAndPruneByLineage(
                    certResourceName, existing, certificateBaseName, priorCertResourceName);
            targetProxyService.applySslProxyCertificates(config, credentials, prune.desired());
        } catch (RuntimeException e) {
            // GCP refuses to delete a certificate a proxy still uses, so this is safe even when the
            // swap went through and only waiting for its operation failed.
            computeSslCertificateService.deleteSslCertificate(certResourceName, credentials);
            throw e;
        }

        // Cleanup superseded resources AFTER the proxy's cert list no longer references them. This
        // prunes EVERY stale version of this cert's lineage (same domain+xref) — not just the single
        // prior tracked in configJson — so a shared proxy doesn't accumulate certs and hit the
        // per-project SSL-certificate quota. Other domains' certs are left in place. Delete failures
        // are logged (GCP resource leak) but don't fail the deployment — the new cert is already live.
        for (String superseded : prune.toDelete()) {
            computeSslCertificateService.deleteSslCertificate(superseded, credentials);
        }

        log.info("{} deployment complete: project={}, sslProxy={}, xref={}",
                CTX, projectId, targetSslProxy, message.getCertificateXref());

        return DeploymentResult.of(targetResourceId, toResultJson(certResourceName));
    }

    void validateScope(GcpProxyScope scope) {
        requireField(scope.projectId(), "scope.projectId");
        requireField(scope.location(), "scope.location");
        requireField(scope.targetSslProxy(), "scope.targetSslProxy");
    }

    private GcpProxyScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, GcpProxyScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private GcpAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return GcpAuthSecret.empty();
        }
        return GcpScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    private static String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }

    private String toResultJson(String certResourceName) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("certificateName", certResourceName);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"certificateName\":\"" + certResourceName + "\"}";
        }
    }
}
