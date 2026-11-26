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
 * GCP target HTTPS proxy deployment — covers ALB, API Gateway, and Cloud CDN target types
 * (all share the Target HTTPS Proxy rotation flow).
 *
 * <p>One credential = one HTTPS proxy. The proxy name lives in the credential scope; the
 * certificate base name is auto-derived per-cert from the domain + xref. Per-cert targets are
 * empty ({@code {}}).
 *
 * <p><b>Uses native {@code compute.sslCertificates}, not Certificate Manager</b>: a Target HTTPS
 * Proxy's {@code sslCertificates[]} field rejects Certificate Manager certificate references
 * ("Cloud certificate reference is not supported for setting SSL certificates in TargetHttpsProxy"),
 * so this adapter creates self-managed compute SslCertificates and swaps them onto the proxy — the
 * same mechanism as {@link GcpProxyNlbDeploymentAdapter}. Compute SslCertificates are immutable, so
 * every deploy creates a new versioned resource, in the proxy's region when the proxy is regional.
 *
 * <p>When the proxy serves from a certificate map, GCP ignores its {@code sslCertificates}, so the
 * certificate is deployed into that map instead ({@link GcpCertificateMapDeployer}).
 */
@Slf4j
@Component
@DeploymentAdapterFor({TargetType.GCP_ALB, TargetType.GCP_API_GW, TargetType.GCP_CLOUD_CDN})
@RequiredArgsConstructor
public class GcpAlbDeploymentAdapter implements DeploymentAdapter {

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final GcpComputeSslCertificateService computeSslCertificateService;
    private final GcpTargetProxyService targetProxyService;
    private final GcpCertificateMapDeployer certificateMapDeployer;
    private final GcpCloudCredentialResolver gcpCredentialResolver;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        String ctx = contextLabel(message.getTargetType());

        GcpProxyScope scope = parseScope(message.getCredentialScopeJson(), ctx);
        validateScope(scope, ctx);

        GcpAuthMode authMode = GcpScopeSupport.parseAuthMode(scope.authMode(), ctx);
        String projectId = scope.projectId().trim();
        String location = scope.location().trim();
        String targetProxy = scope.targetProxy().trim();
        String certificateBaseName = GcpNameUtils.deriveBaseName(
                message.getDomain(), message.getCertificateXref());

        GcpAuthSecret kv = readKvSecret(message, ctx);
        GcpAuthScope authScope = GcpScopeSupport.toAuthScope(
                projectId, location, scope.impersonateServiceAccount());
        GoogleCredentials credentials = gcpCredentialResolver.resolve(authMode, authScope, kv, ctx);

        // Compute SslCertificate is immutable — always create a new versioned resource, swap it
        // onto the Target HTTPS Proxy, then delete the prior resource. Target HTTPS Proxies reject
        // Certificate Manager certificate references on setSslCertificates (GCP: "Cloud certificate
        // reference is not supported for setting SSL certificates in TargetHttpsProxy"), so this
        // adapter uses native compute SslCertificates — the same approach as the Proxy NLB adapter.
        // GcpDeploymentSupport#readPriorCertResourceName is reused because the configJson key is the
        // same ("certificateName") across all GCP adapters even though the URL shape differs.
        String priorCertResourceName = GcpDeploymentSupport.readPriorCertResourceName(
                objectMapper, message.getConfigJson(), "certificateName");

        // Read the proxy first so a proxy the agent cannot deploy to fails before a cert is created.
        GcpTargetProxyConfig config = new GcpTargetProxyConfig(projectId, location, targetProxy);
        GcpTargetProxyState proxy = targetProxyService.fetchHttpsProxy(config, credentials);
        String targetResourceId = "gcp://target-https-proxy/" + targetProxy;
        if (proxy.usesCertificateMap()) {
            // GCP ignores sslCertificates while a map is attached, so the map is what serves.
            GcpCertificateMapDeployer.MapDeployment deployment = certificateMapDeployer.deployToProxyMap(
                    proxy.certificateMap(), certificateBaseName, priorCertResourceName, bundle, credentials);
            log.info("{} deployment complete through certificate map: project={}, proxy={}, map={}, xref={}",
                    ctx, projectId, targetProxy, deployment.certificateMap(), message.getCertificateXref());
            return DeploymentResult.of(targetResourceId,
                    GcpDeploymentSupport.proxyMapResultConfigJson(objectMapper, deployment));
        }
        if (GcpTargetProxyService.looksLikeCertManagerResourceName(priorCertResourceName)) {
            // The prior deploy went through a map since detached; compute pruning must not touch it.
            priorCertResourceName = null;
        }

        String certificateId = GcpNameUtils.versionedId(certificateBaseName);
        log.info("{} create new: project={}, location={}, proxy={}, certId={}, xref={}",
                ctx, projectId, location, targetProxy, certificateId, message.getCertificateXref());
        String certResourceName = computeSslCertificateService.createSslCertificate(
                projectId, location, certificateId, bundle, credentials);

        GcpDeploymentSupport.CertificatePrune prune;
        try {
            // Re-read after the create so the read-modify-write window does not span the create's
            // operation; setSslCertificates has no fingerprint and other deploys may share the proxy.
            List<String> existing = targetProxyService.fetchHttpsProxy(config, credentials).sslCertificates();
            prune = GcpDeploymentSupport.mergeAndPruneByLineage(
                    certResourceName, existing, certificateBaseName, priorCertResourceName);
            targetProxyService.applyHttpsProxyCertificates(config, credentials, prune.desired());
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

        log.info("{} deployment complete: project={}, proxy={}, xref={}",
                ctx, projectId, targetProxy, message.getCertificateXref());

        return DeploymentResult.of(targetResourceId, toResultJson(certResourceName));
    }

    void validateScope(GcpProxyScope scope, String ctx) {
        requireField(scope.projectId(), "scope.projectId", ctx);
        requireField(scope.location(), "scope.location", ctx);
        requireField(scope.targetProxy(), "scope.targetProxy", ctx);
    }

    private static String contextLabel(TargetType t) {
        if (t == TargetType.GCP_API_GW) return "GCP API Gateway";
        if (t == TargetType.GCP_CLOUD_CDN) return "GCP Cloud CDN";
        return "GCP ALB";
    }

    private GcpProxyScope parseScope(String json, String ctx) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    ctx + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, GcpProxyScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + ctx + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private GcpAuthSecret readKvSecret(CertDeploymentMessage message, String ctx) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return GcpAuthSecret.empty();
        }
        return GcpScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), ctx);
    }

    private static String requireField(String value, String name, String ctx) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    ctx + " missing required field: " + name);
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
