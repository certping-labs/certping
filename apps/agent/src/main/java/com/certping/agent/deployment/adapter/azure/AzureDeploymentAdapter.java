// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateContentType;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.ImportCertificateOptions;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.cloud.azure.AzureAuthMode;
import com.certping.agent.deployment.cloud.azure.AzureAuthScope;
import com.certping.agent.deployment.cloud.azure.AzureAuthSecret;
import com.certping.agent.deployment.cloud.azure.AzureCloudCredentialResolver;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Azure Key Vault deployment — one credential = one vault.
 *
 * <p>Scope: {@link AzureKvScope} — vault URI lives here, not in per-cert targets.
 * <br>Targets: {@link AzureKvTargets} — flat {@code {"certificateName":"..."}} (optional).
 * If omitted on first deploy, the adapter auto-derives the KV cert name from the cert's
 * primary domain via {@link CertificateIdentityUtils#toAzureKvCertificateName}. Subsequent
 * rotations lock the name via {@code result.certificateName} so renewals always land on
 * the same KV cert.
 * <br>Result (returned as agent result, stored flat): {@code {"certificateName":"...","version":"..."}}
 *
 * <p>Auth: SERVICE_PRINCIPAL (clientId+clientSecret in KV) or WORKLOAD_IDENTITY (no KV secret).
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AZURE_KV)
@RequiredArgsConstructor
public class AzureDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "Azure Key Vault";

    private final SecretStore secretStore;
    private final AzureCloudCredentialResolver azureCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AzureKvScope scope = parseScope(message.getCredentialScopeJson());
        AzureAuthMode authMode = AzureScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);
        String vaultUri = scope.vaultUri().trim();

        AzureKvTargets targets = parseTargets(message.getTargetsJson());
        // Effective cert name: prior result locks → operator-supplied targets → auto-derive from domain.
        String certName = resolveCertName(targets, message);
        if (!certName.matches("^[a-zA-Z0-9-]{1,127}$")) {
            throw new PermanentAgentException("DEPLOY_CERT_NAME_INVALID",
                    "Azure KV certificateName must be 1-127 alphanumeric or hyphen characters: '" + certName + "'");
        }

        // Both branches route through the shared credential resolver so the credential we use
        // matches scope.clientId — not the pod's default AZURE_CLIENT_ID env var. DefaultAzureCredential
        // would pick up whatever clientId the workload-identity webhook injected from the SA
        // annotation, which can belong to a different app than the one this CertPing credential
        // is configured for (e.g. the cluster's platform UAMI). The resolver builds a
        // WorkloadIdentityCredential with scope.clientId() explicitly, so token exchange targets
        // the right app.
        TokenCredential azureCredential;
        AzureAuthScope authScope = AzureScopeSupport.toAuthScope(
                scope.tenantId(), null, scope.clientId(), null);
        if (authMode == AzureAuthMode.WORKLOAD_IDENTITY) {
            log.debug("{}: using WORKLOAD_IDENTITY (clientId={})", CTX, scope.clientId());
            azureCredential = azureCredentialResolver.resolve(authMode, authScope, AzureAuthSecret.empty(), CTX);
        } else {
            AzureAuthSecret kv = readKvSecret(message);
            azureCredential = azureCredentialResolver.resolve(authMode, authScope, kv, CTX);
        }

        String domain = requireDomain(message.getDomain(), message.getCertificateXref());
        String pkcs8Key = AzurePemSupport.toPkcs8(bundle.privateKey());
        String pemForImport = pkcs8Key.trim() + "\n" + bundle.fullChain().trim();

        log.info("Azure KV deploy: vaultUri={}, certName={}, xref={}",
                vaultUri, certName, message.getCertificateXref());

        try {
            CertificateClient certClient = new CertificateClientBuilder()
                    .vaultUrl(vaultUri)
                    .credential(azureCredential)
                    .buildClient();

            ImportCertificateOptions options =
                    new ImportCertificateOptions(certName, pemForImport.getBytes());
            options.setEnabled(true);
            // Without this policy, Key Vault interprets the binary payload as PKCS#12 by default
            // and rejects PEM bytes with "PKCS#12 X.509 certificate content can not be read".
            // The AGW and AFD adapters import as PKCS12; this one stays on PEM (one less conversion
            // step), so the content type must be flagged explicitly.
            options.setPolicy(new CertificatePolicy("Self", "CN=" + certName)
                    .setContentType(CertificateContentType.PEM));
            options.setTags(buildTags(domain, message));

            KeyVaultCertificateWithPolicy imported = certClient.importCertificate(options);
            String certId = imported.getId();
            String version = extractVersionFromId(certId);
            log.info("Azure KV imported: vaultUri={}, certName={}, version={}", vaultUri, certName, version);

            return DeploymentResult.of(certId, toResultJson(certName, version));

        } catch (HttpResponseException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure KV upsert", certName, e);
            }
            int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
            if (AzureErrorClassifier.isPermissionDenied(e)) {
                throw new PermanentAgentException(AzureErrorClassifier.PERMISSION_DENIED,
                        "Azure KV permission denied at " + vaultUri + " (HTTP " + status + "): " + e.getMessage(), e);
            }
            if (status == 400) {
                throw new PermanentAgentException("DEPLOY_CERT_REJECTED",
                        "Azure KV rejected the certificate import (HTTP 400): " + e.getMessage(), e);
            }
            if (status == 401) {
                throw new PermanentAgentException("DEPLOY_ACCESS_DENIED",
                        "Azure KV access denied at " + vaultUri + " (HTTP " + status + "): " + e.getMessage(), e);
            }
            throw new TransientAgentException("DEPLOY_AZURE_HTTP_ERROR",
                    "Azure KV HTTP error (HTTP " + status + "): " + e.getMessage(), e);
        } catch (PermanentAgentException | TransientAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure KV upsert", certName, e);
            }
            throw new PermanentAgentException("DEPLOY_AZURE_FAILED",
                    "Azure KV deployment failed: " + e.getMessage(), e);
        }
    }

    void validateScope(AzureKvScope scope) {
        String vaultUri = requireField(scope.vaultUri(), "scope.vaultUri");
        if (!vaultUri.matches("^https://[a-zA-Z0-9-]+\\.vault\\.azure\\.net/?$")) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " scope.vaultUri has invalid format: " + vaultUri);
        }
    }

    private AzureKvScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AzureKvScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AzureKvTargets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new AzureKvTargets(null);
        }
        try {
            return objectMapper.readValue(json, AzureKvTargets.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    "Failed to parse " + CTX + " targetsJson: " + e.getMessage(), e);
        }
    }

    private AzureAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AzureAuthSecret.empty();
        }
        return AzureScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    /**
     * Resolve the effective KV cert name. Priority: operator-supplied {@code targets.certificateName}
     * (rename support — the operator's current intent always wins) → prior {@code result.certificateName}
     * (renewal stability when targets is blank) → auto-derived from the cert's primary domain.
     *
     * <p>If the operator changes {@code targets.certificateName}, the next deploy creates a new
     * KV cert under the new name; the old KV cert keeps existing in the vault (consumers pulling
     * by old name keep getting the old version) until the operator purges it.
     */
    private String resolveCertName(AzureKvTargets targets, CertDeploymentMessage message) {
        if (targets.certificateName() != null && !targets.certificateName().isBlank()) {
            return targets.certificateName().trim();
        }
        String prior = readPriorCertName(message.getConfigJson());
        if (prior != null) return prior;
        String derived = CertificateIdentityUtils.toAzureKvCertificateName(message.getDomain());
        if (derived.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " could not derive certificateName: targets.certificateName missing and "
                            + "message.domain is blank/unusable");
        }
        return derived;
    }

    private String readPriorCertName(String configJson) {
        if (configJson == null || configJson.isBlank()) return null;
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode val = root.get("certificateName");
            if (val != null && val.isString() && !val.asString().isBlank()) {
                return val.asString().trim();
            }
        } catch (Exception e) {
            log.warn("{}: failed to parse prior result configJson — treating as first deploy: {}",
                    CTX, e.getMessage());
        }
        return null;
    }

    private String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }

    private String requireDomain(String rawDomain, String certXref) {
        String domain = CertificateIdentityUtils.normaliseDomain(rawDomain);
        if (domain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                    "CERT_DEPLOYMENT message missing required domain for xref=" + certXref);
        }
        return domain;
    }

    /** Cert id format: {@code https://<vault>/certificates/<name>/<version>}. */
    private String extractVersionFromId(String certId) {
        if (certId == null) return null;
        int last = certId.lastIndexOf('/');
        if (last < 0 || last == certId.length() - 1) return null;
        return certId.substring(last + 1);
    }

    private Map<String, String> buildTags(String domain, CertDeploymentMessage message) {
        Map<String, String> tags = new HashMap<>();
        tags.put("ManagedBy", "certping-agent");
        if (message.getOrganizationId() != null && !message.getOrganizationId().isBlank()) {
            tags.put("OrganizationId", message.getOrganizationId());
        }
        if (domain != null && !domain.isBlank()) tags.put("Domain", domain);
        return tags;
    }

    private String toResultJson(String certName, String version) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("certificateName", certName);
            if (version != null) root.put("version", version);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"certificateName\":\"" + certName + "\"}";
        }
    }
}
