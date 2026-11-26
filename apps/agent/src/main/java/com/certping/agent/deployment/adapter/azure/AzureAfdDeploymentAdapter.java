// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.management.exception.ManagementError;
import com.azure.core.management.exception.ManagementException;
import com.azure.core.management.profile.AzureProfile;
import com.azure.core.util.Context;
import com.azure.resourcemanager.cdn.CdnManager;
import com.azure.resourcemanager.cdn.fluent.models.AfdDomainInner;
import com.azure.resourcemanager.cdn.fluent.models.SecretInner;
import com.azure.resourcemanager.cdn.models.AfdCertificateType;
import com.azure.resourcemanager.cdn.models.AfdDomainHttpsParameters;
import com.azure.resourcemanager.cdn.models.AfdDomainUpdateParameters;
import com.azure.resourcemanager.cdn.models.CustomerCertificateParameters;
import com.azure.resourcemanager.cdn.models.ResourceReference;
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
import com.certping.agent.deployment.util.PemPfxUtils;
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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Azure Front Door deployment adapter.
 *
 * <p>One credential = one AFD profile. Key Vault URI and available custom domains live in
 * the credential scope. Per-cert {@code certificateName} (KV cert name) and {@code secretName}
 * (AFD Secret resource name on the profile) live in targets so one profile can host many
 * independent certs. Targets also select a subset of {@code scope.customDomains}.
 *
 * <p>Result locks both names on first deploy: subsequent rotations always reuse the same KV
 * cert name and AFD Secret resource (avoids orphaning resources if operator edits targets).
 *
 * <p>Three-step flow: import cert into KV → upsert AFD Secret → bind to target custom domains.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AZURE_AFD)
@RequiredArgsConstructor
public class AzureAfdDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "Azure Front Door";

    private final SecretStore secretStore;
    private final AzureCloudCredentialResolver azureCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AzureAfdScope scope = parseScope(message.getCredentialScopeJson());
        AzureAuthMode authMode = AzureScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);

        AzureAfdTargets targets = parseTargets(message.getTargetsJson());
        List<String> domainNames = validateTargets(targets, scope);

        // Resolve effective names: prior result locks them; first deploy uses targets.
        String effectiveCertificateName = resolveEffectiveName(
                readPriorResultField(message.getConfigJson(), "certificateName"),
                targets.certificateName(),
                "targets.certificateName");
        String effectiveSecretName = resolveEffectiveName(
                readPriorResultField(message.getConfigJson(), "secretName"),
                targets.secretName(),
                "targets.secretName");

        AzureAuthSecret kv = readKvSecret(message);
        AzureAuthScope authScope = AzureScopeSupport.toAuthScope(
                scope.tenantId(), scope.subscriptionId(), scope.clientId(), scope.federatedTokenFile());
        TokenCredential azureCredential = azureCredentialResolver.resolve(authMode, authScope, kv, CTX);
        AzureProfile profile = azureCredentialResolver.buildProfile(authScope, CTX);

        log.info("Azure AFD deploy: rg={}, profile={}, secret={}, domainNames={}",
                scope.resourceGroup(), scope.profileName(), effectiveSecretName, domainNames.size());

        try {
            CdnManager cdnManager = CdnManager.authenticate(azureCredential, profile);

            // 1. Import to KV (PFX)
            String versionedKvSecretId = importToKeyVault(
                    bundle, scope.keyVaultUri(), effectiveCertificateName, azureCredential);
            // AFD's CustomerCertificateParameters.secretSource.id MUST be the ARM resource ID
            // of the KV secret, not the data-plane URL (https://{vault}.vault.azure.net/secrets/...).
            // Azure rejects the URL form with LinkedInvalidPropertyId.
            String secretSourceId = buildKvSecretArmId(scope, effectiveCertificateName);

            // 2. Upsert AFD Secret (always useLatestVersion=true)
            upsertAfdSecret(cdnManager, scope, effectiveSecretName, secretSourceId);

            // 3. Bind to custom domains
            String afdSecretResourceId = buildAfdSecretResourceId(scope, effectiveSecretName);
            for (String domain : domainNames) {
                bindSecretToCustomDomain(cdnManager, scope, domain, afdSecretResourceId);
            }

            return DeploymentResult.of(afdSecretResourceId,
                    toResultJson(effectiveCertificateName, effectiveSecretName));

        } catch (ManagementException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure AFD update", scope.profileName(), e);
            }
            int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
            String azureDetail = formatAzureManagementError(e.getValue(), 0);
            String responseBody = safeReadBody(e);
            log.error("{} update failed: status={}, azureError={}, responseBody={}, message={}",
                    CTX, status, azureDetail, responseBody, e.getMessage(), e);
            String combined = CTX + " (HTTP " + status + "): "
                    + (azureDetail.isBlank() ? e.getMessage() : azureDetail)
                    + (responseBody.isBlank() ? "" : " — body: " + responseBody);
            if (AzureErrorClassifier.isPermissionDenied(e)) {
                throw new PermanentAgentException(AzureErrorClassifier.PERMISSION_DENIED, combined, e);
            }
            if (status == 400) {
                throw new PermanentAgentException("DEPLOY_CERT_REJECTED", combined, e);
            }
            if (status == 401) {
                throw new PermanentAgentException("DEPLOY_ACCESS_DENIED", combined, e);
            }
            if (status == 404) {
                throw new PermanentAgentException("DEPLOY_RESOURCE_NOT_FOUND", combined, e);
            }
            if (status == 409 || status == 412) {
                throw new PermanentAgentException("DEPLOY_AZURE_CONFLICT", combined, e);
            }
            throw new TransientAgentException("DEPLOY_AZURE_HTTP_ERROR", combined, e);
        } catch (HttpResponseException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure AFD update", scope.profileName(), e);
            }
            int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
            String responseBody = safeReadBody(e);
            log.error("{} HTTP error: status={}, responseBody={}, message={}",
                    CTX, status, responseBody, e.getMessage(), e);
            String combined = CTX + " (HTTP " + status + "): " + e.getMessage()
                    + (responseBody.isBlank() ? "" : " — body: " + responseBody);
            if (AzureErrorClassifier.isPermissionDenied(e)) {
                throw new PermanentAgentException(AzureErrorClassifier.PERMISSION_DENIED, combined, e);
            }
            if (status == 400) {
                throw new PermanentAgentException("DEPLOY_CERT_REJECTED", combined, e);
            }
            if (status == 401) {
                throw new PermanentAgentException("DEPLOY_ACCESS_DENIED", combined, e);
            }
            throw new TransientAgentException("DEPLOY_AZURE_HTTP_ERROR", combined, e);
        } catch (PermanentAgentException | TransientAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure AFD update", scope.profileName(), e);
            }
            log.error("{} unexpected failure: {}", CTX, e.getMessage(), e);
            throw new PermanentAgentException("DEPLOY_AZURE_FAILED",
                    "Azure Front Door deployment failed: " + e.getMessage(), e);
        }
    }

    void validateScope(AzureAfdScope scope) {
        requireField(scope.subscriptionId(), "scope.subscriptionId");
        requireField(scope.resourceGroup(), "scope.resourceGroup");
        requireField(scope.profileName(), "scope.profileName");
        requireField(scope.keyVaultUri(), "scope.keyVaultUri");
        if (scope.customDomains() == null || scope.customDomains().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: scope.customDomains");
        }
    }

    List<String> validateTargets(AzureAfdTargets targets, AzureAfdScope scope) {
        if (targets.domainNames() == null || targets.domainNames().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    CTX + " requires non-empty targets.domainNames");
        }
        Set<String> scopeDomains = new LinkedHashSet<>(scope.customDomains());
        for (String name : targets.domainNames()) {
            if (name == null || name.isBlank()) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        CTX + " domainNames entries must be non-blank");
            }
            if (!scopeDomains.contains(name.trim())) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        "domain '" + name + "' is not in the credential's scope.customDomains");
            }
        }
        return targets.domainNames();
    }

    private String importToKeyVault(CertificateBundle bundle,
                                    String keyVaultUri,
                                    String certificateName,
                                    TokenCredential azureCredential) {
        try {
            CertificateClient certClient = new CertificateClientBuilder()
                    .vaultUrl(keyVaultUri)
                    .credential(azureCredential)
                    .buildClient();
            byte[] pfxBytes = PemPfxUtils.toPkcs12Bytes(bundle, null);
            ImportCertificateOptions options = new ImportCertificateOptions(certificateName, pfxBytes);
            options.setEnabled(true);
            // Explicitly tell Key Vault these are PKCS12 bytes — without the policy, KV defaults
            // to PEM detection and rejects the binary payload with
            // "The specified PEM X.509 certificate content is in an unexpected format".
            options.setPolicy(new CertificatePolicy("Self", "CN=" + certificateName)
                    .setContentType(CertificateContentType.PKCS12));

            KeyVaultCertificateWithPolicy imported = certClient.importCertificate(options);
            String secretId = imported.getSecretId();
            if (secretId == null || secretId.isBlank()) {
                throw new PermanentAgentException("DEPLOY_RESULT_NULL_RESOURCE_ID",
                        "Key Vault import returned empty secretId for Azure AFD");
            }
            return secretId;
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure KV import (AFD)", certificateName, e);
            }
            if (e instanceof HttpResponseException h && AzureErrorClassifier.isPermissionDenied(h)) {
                throw new PermanentAgentException(AzureErrorClassifier.PERMISSION_DENIED,
                        "Key Vault import denied for Front Door: " + e.getMessage(), e);
            }
            throw new PermanentAgentException("DEPLOY_AZURE_KV_IMPORT_FAILED",
                    "Failed to import cert into Key Vault for Front Door: " + e.getMessage(), e);
        }
    }

    private void upsertAfdSecret(CdnManager cdnManager,
                                 AzureAfdScope scope,
                                 String secretName,
                                 String kvSecretId) {
        // AFD's SDK.create() is NOT idempotent — it returns 409 "That resource name isn't
        // available" if a Secret with this name already exists, even when the new payload is
        // identical. For renewals (which re-import the same cert to the same KV cert name with
        // useLatestVersion=true) the existing Secret already references the right KV path
        // and will automatically pick up the latest version — so an existing matching Secret
        // is a no-op. Only delete + recreate when the existing Secret points at a different
        // KV source.
        SecretInner existing = null;
        try {
            existing = cdnManager.serviceClient().getSecrets()
                    .get(scope.resourceGroup(), scope.profileName(), secretName);
        } catch (ManagementException e) {
            int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
            if (status != 404) {
                throw e;
            }
            // 404 → no existing Secret, fall through to create
        }
        if (existing != null && referencesSameKvSecret(existing, kvSecretId)) {
            log.info("AFD secret already points at the latest KV cert — no-op: profile={}, secret={}",
                    scope.profileName(), secretName);
            return;
        }
        if (existing != null) {
            log.info("AFD secret exists but references a different KV source — deleting before recreate: profile={}, secret={}",
                    scope.profileName(), secretName);
            cdnManager.serviceClient().getSecrets()
                    .delete(scope.resourceGroup(), scope.profileName(), secretName);
        }
        SecretInner inner = new SecretInner().withParameters(
                new CustomerCertificateParameters()
                        .withSecretSource(new ResourceReference().withId(kvSecretId))
                        .withUseLatestVersion(true));
        cdnManager.serviceClient().getSecrets().create(
                scope.resourceGroup(), scope.profileName(), secretName, inner, Context.NONE);
        log.info("AFD secret upserted: profile={}, secret={}", scope.profileName(), secretName);
    }

    /**
     * True when an existing AFD Secret already references the same unversioned KV cert id —
     * i.e. a renewal can no-op because {@code useLatestVersion=true} makes AFD auto-pick the
     * new version of the same cert.
     */
    private boolean referencesSameKvSecret(SecretInner existing, String kvSecretId) {
        if (existing == null || existing.parameters() == null) {
            return false;
        }
        if (!(existing.parameters() instanceof CustomerCertificateParameters params)) {
            return false;
        }
        if (params.secretSource() == null || params.secretSource().id() == null) {
            return false;
        }
        boolean useLatest = Boolean.TRUE.equals(params.useLatestVersion());
        return useLatest && kvSecretId.equalsIgnoreCase(params.secretSource().id());
    }

    private void bindSecretToCustomDomain(CdnManager cdnManager,
                                          AzureAfdScope scope,
                                          String domainName,
                                          String afdSecretResourceId) {
        // AFD custom-domain ARM resource names cannot contain dots,
        // but the configured domainName is the DNS hostname. Resolve
        // the resource name by hostName lookup.
        AfdDomainInner existing = cdnManager.serviceClient().getAfdCustomDomains()
                .listByProfile(scope.resourceGroup(), scope.profileName())
                .stream()
                .filter(d -> domainName.equalsIgnoreCase(d.hostname()))
                .findFirst()
                .orElseThrow(() -> new PermanentAgentException("DEPLOY_RESOURCE_NOT_FOUND",
                        "AFD custom domain not found by hostName: " + domainName));
        String resourceName = existing.name();
        AfdDomainHttpsParameters https = new AfdDomainHttpsParameters()
                .withCertificateType(AfdCertificateType.CUSTOMER_CERTIFICATE)
                .withSecret(new ResourceReference().withId(afdSecretResourceId));
        AfdDomainUpdateParameters update = new AfdDomainUpdateParameters().withTlsSettings(https);
        cdnManager.serviceClient().getAfdCustomDomains().beginUpdate(
                scope.resourceGroup(), scope.profileName(), resourceName, update, Context.NONE)
                .getFinalResult();
        log.info("AFD domain TLS bound: domain={}, resourceName={}", domainName, resourceName);
    }

    /**
     * Builds the ARM resource ID of the unversioned KV secret in the form
     * {@code /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault}/secrets/{name}}.
     *
     * <p>AFD's {@code CustomerCertificateParameters.secretSource.id} requires this resource-ID
     * form — the data-plane URL ({@code https://{vault}.vault.azure.net/secrets/{name}}) is
     * rejected by ARM with {@code LinkedInvalidPropertyId}.
     *
     * <p>Resolution order:
     * <ul>
     *   <li>{@code subscriptionId}: {@code scope.keyVaultSubscriptionId} → {@code scope.subscriptionId}</li>
     *   <li>{@code resourceGroup}: {@code scope.keyVaultResourceGroup} → {@code scope.resourceGroup}</li>
     *   <li>{@code vaultName}: parsed from {@code scope.keyVaultUri} (host's first DNS label)</li>
     * </ul>
     */
    String buildKvSecretArmId(AzureAfdScope scope, String certificateName) {
        String kvSub = (scope.keyVaultSubscriptionId() != null && !scope.keyVaultSubscriptionId().isBlank())
                ? scope.keyVaultSubscriptionId().trim()
                : scope.subscriptionId();
        String kvRg = (scope.keyVaultResourceGroup() != null && !scope.keyVaultResourceGroup().isBlank())
                ? scope.keyVaultResourceGroup().trim()
                : scope.resourceGroup();
        String vaultName = parseVaultNameFromUri(scope.keyVaultUri());
        return "/subscriptions/" + kvSub
                + "/resourceGroups/" + kvRg
                + "/providers/Microsoft.KeyVault/vaults/" + vaultName
                + "/secrets/" + certificateName;
    }

    private String parseVaultNameFromUri(String keyVaultUri) {
        if (keyVaultUri == null || keyVaultUri.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " keyVaultUri is required to build KV ARM resource id");
        }
        // Strip scheme and any path: "https://my-kv.vault.azure.net/" -> "my-kv.vault.azure.net"
        String trimmed = keyVaultUri.trim();
        int schemeEnd = trimmed.indexOf("://");
        String hostAndPath = schemeEnd >= 0 ? trimmed.substring(schemeEnd + 3) : trimmed;
        int slash = hostAndPath.indexOf('/');
        String host = slash >= 0 ? hostAndPath.substring(0, slash) : hostAndPath;
        int dot = host.indexOf('.');
        if (dot <= 0) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " keyVaultUri '" + keyVaultUri + "' is not a valid Key Vault URI");
        }
        return host.substring(0, dot);
    }

    String buildAfdSecretResourceId(AzureAfdScope scope, String secretName) {
        return "/subscriptions/" + scope.subscriptionId()
                + "/resourceGroups/" + scope.resourceGroup()
                + "/providers/Microsoft.Cdn/profiles/" + scope.profileName()
                + "/secrets/" + secretName;
    }

    private AzureAfdScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AzureAfdScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AzureAfdTargets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new AzureAfdTargets(null, null, List.of());
        }
        try {
            return objectMapper.readValue(json, AzureAfdTargets.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    "Failed to parse " + CTX + " targetsJson: " + e.getMessage(), e);
        }
    }

    /**
     * Resolve an effective name for a per-cert resource (KV cert name, AFD Secret name).
     * Targets wins (operator's current intent — supports rename), else prior {@code result.<field>}
     * (renewal stability when targets is blank), else error (first deploy with no targets).
     *
     * <p>Rename via targets creates a new KV cert / AFD Secret resource at the new name; the old
     * resources (KV cert and AFD Secret on the profile) become orphan once the custom-domain TLS
     * binding is repointed to the new Secret. Operator owns cleanup of the old resources.
     */
    private String resolveEffectiveName(String prior, String fromTargets, String fieldName) {
        if (fromTargets != null && !fromTargets.isBlank()) return fromTargets.trim();
        if (prior != null) return prior;
        throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                CTX + " requires " + fieldName + " on first deploy");
    }

    /**
     * Read a string field from the prior deployment {@code result.configJson} (e.g.
     * {@code certificateName} or {@code secretName}) so subsequent rotations lock onto
     * the same KV cert / AFD Secret resource and don't orphan resources. Returns null on
     * first deploy or if the configJson is empty/unparseable/missing the field.
     */
    private String readPriorResultField(String configJson, String fieldName) {
        if (configJson == null || configJson.isBlank()) return null;
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode val = root.get(fieldName);
            if (val != null && val.isString() && !val.asString().isBlank()) {
                return val.asString().trim();
            }
        } catch (Exception e) {
            log.warn("{}: failed to parse prior result configJson — treating as first deploy: {}",
                    CTX, e.getMessage());
        }
        return null;
    }

    private AzureAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AzureAuthSecret.empty();
        }
        return AzureScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    private String requireField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " missing required field: " + name);
        }
        return value.trim();
    }

    private String toResultJson(String certificateName, String secretName) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("certificateName", certificateName);
            root.put("secretName", secretName);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"certificateName\":\"" + certificateName + "\"}";
        }
    }

    /**
     * Recursively flattens a {@link ManagementError} into a single human-readable string. Walks
     * {@code details[]} so nested Azure errors (e.g. KeyVault validation, AFD policy violations)
     * aren't dropped.
     */
    private String formatAzureManagementError(ManagementError err, int depth) {
        if (err == null || depth > 5) return "";
        StringBuilder sb = new StringBuilder();
        if (err.getCode() != null) sb.append("code=").append(err.getCode());
        if (err.getMessage() != null) {
            if (sb.length() > 0) sb.append(", ");
            sb.append("message=").append(err.getMessage());
        }
        if (err.getTarget() != null) {
            if (sb.length() > 0) sb.append(", ");
            sb.append("target=").append(err.getTarget());
        }
        List<? extends ManagementError> details = err.getDetails();
        if (details != null && !details.isEmpty()) {
            sb.append(", details=[");
            for (int i = 0; i < details.size(); i++) {
                if (i > 0) sb.append("; ");
                sb.append(formatAzureManagementError(details.get(i), depth + 1));
            }
            sb.append("]");
        }
        return sb.toString();
    }

    private String safeReadBody(HttpResponseException e) {
        try {
            if (e.getResponse() == null) return "";
            String body = e.getResponse().getBodyAsString().block();
            return body == null ? "" : body;
        } catch (Exception ignored) {
            return "";
        }
    }
}
