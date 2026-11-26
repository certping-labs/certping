// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.management.exception.ManagementError;
import com.azure.core.management.exception.ManagementException;
import com.azure.core.management.profile.AzureProfile;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.network.models.ApplicationGateway;
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

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Azure Application Gateway deployment — one credential = one App Gateway.
 *
 * <p>Scope: {@link AzureAppGatewayScope} — single resourceGroup, appGateway, available
 * listeners, sslCertName, and keyVaultUri live here.
 * <br>Targets: {@link AzureAppGatewayTargets} — selects which listeners (subset of scope.listeners).
 * <br>Result: {@code {"certificateName": "...", "keyVaultSecretId": "..."}}.
 *
 * <p>The adapter imports the cert into Key Vault, then updates the AGW's SSL certificate
 * and points the selected listeners to it.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AZURE_APP_GW)
@RequiredArgsConstructor
public class AzureAppGatewayDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "Azure App Gateway";

    private final SecretStore secretStore;
    private final AzureCloudCredentialResolver azureCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AzureAppGatewayScope scope = parseScope(message.getCredentialScopeJson());
        AzureAuthMode authMode = AzureScopeSupport.parseAuthMode(scope.authMode(), CTX);

        validateScope(scope);

        AzureAppGatewayTargets targets = parseTargets(message.getTargetsJson());
        if (targets.listenerNames() == null || targets.listenerNames().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    CTX + " requires non-empty targets.listenerNames");
        }

        Set<String> allowed = new LinkedHashSet<>(scope.listeners());
        for (String listener : targets.listenerNames()) {
            if (!allowed.contains(listener)) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        "listener '" + listener + "' is not in the credential's scope.listeners");
            }
        }

        // Resolve effective cert name: targets wins (rename support — operator's current intent),
        // else prior result.certificateName (renewal stability), else error.
        // NOTE: if the operator renames via targets.sslCertName, the old AGW SSL cert resource
        // becomes orphan on the gateway (listeners get repointed to the new SSL cert). The
        // operator owns the cleanup of the old resource.
        String sslCertName;
        if (targets.sslCertName() != null && !targets.sslCertName().isBlank()) {
            sslCertName = targets.sslCertName().trim();
        } else {
            String priorCertName = readPriorCertName(message.getConfigJson());
            if (priorCertName != null) {
                sslCertName = priorCertName;
            } else {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        CTX + " requires targets.sslCertName on first deploy");
            }
        }

        AzureAuthSecret kv = readKvSecret(message);
        AzureAuthScope authScope = AzureScopeSupport.toAuthScope(
                scope.tenantId(), scope.subscriptionId(), scope.clientId(), scope.federatedTokenFile());
        TokenCredential azureCredential = azureCredentialResolver.resolve(authMode, authScope, kv, CTX);
        AzureProfile profile = azureCredentialResolver.buildProfile(authScope, CTX);

        String domain = requireDomain(message.getDomain(), message.getCertificateXref());
        // AGW retrieves the KV secret and expects PFX/PKCS12 binary — importing as PEM here
        // lands in KV but AGW then fails with ApplicationGatewaySslCertificateInvalidData
        // ("Data or Password for certificate is invalid"). Build a passwordless PFX from the
        // PEM bundle and let KV store it natively.
        byte[] pfxBytes = PemPfxUtils.toPkcs12Bytes(bundle, null);

        String rg = scope.resourceGroup().trim();
        String gw = scope.appGateway().trim();
        String keyVaultUri = scope.keyVaultUri().trim();

        log.info("{} deploy: rg={}, agw={}, listeners={}, kv={}", CTX, rg, gw,
                targets.listenerNames().size(), keyVaultUri);

        String secretId;
        String agwId;

        try {
            secretId = importToKeyVault(keyVaultUri, sslCertName, pfxBytes, azureCredential);

            AzureResourceManager azure = AzureResourceManager
                    .authenticate(azureCredential, profile)
                    .withSubscription(scope.subscriptionId());

            ApplicationGateway agw = azure.applicationGateways().getByResourceGroup(rg, gw);
            if (agw == null) {
                throw new PermanentAgentException("DEPLOY_RESOURCE_NOT_FOUND",
                        "Azure Application Gateway not found: " + rg + "/" + gw);
            }
            agwId = agw.id();

            ApplicationGateway.Update update = agw.update()
                    .defineSslCertificate(sslCertName)
                    .withKeyVaultSecretId(secretId)
                    .attach();
            for (String listener : targets.listenerNames()) {
                update = update.updateListener(listener)
                        .withSslCertificate(sslCertName)
                        .parent();
            }
            update.apply();

            log.info("{} updated AGW {}/{} — cert={}, listeners={}", CTX, rg, gw,
                    sslCertName, targets.listenerNames());

        } catch (ManagementException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure AGW update", rg + "/" + gw, e);
            }
            // ManagementException wraps the failed long-running operation (LRO) result. The default
            // message ("Long running operation is Failed or Cancelled") is useless on its own —
            // the actual Azure error details live in e.getValue() (ManagementError: code/message/
            // target/details) and the response body. Surface all three so we can diagnose without
            // re-running with debug logging enabled.
            int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
            String azureDetail = formatAzureManagementError(e.getValue(), 0);
            String responseBody = safeReadBody(e);
            log.error("{} update failed at {}/{}: status={}, azureError={}, responseBody={}, message={}",
                    CTX, rg, gw, status, azureDetail, responseBody, e.getMessage(), e);

            String combined = CTX + " " + rg + "/" + gw + " (HTTP " + status + "): "
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
            // 5xx, -1 (no response — e.g. LRO timeout/cancel), or other unhandled status → retry.
            throw new TransientAgentException("DEPLOY_AZURE_HTTP_ERROR", combined, e);
        } catch (HttpResponseException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure AGW update", rg + "/" + gw, e);
            }
            int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
            String responseBody = safeReadBody(e);
            log.error("{} HTTP error at {}/{}: status={}, responseBody={}, message={}",
                    CTX, rg, gw, status, responseBody, e.getMessage(), e);
            String combined = CTX + " " + rg + "/" + gw + " (HTTP " + status + "): " + e.getMessage()
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
                throw rl.get().toRetryable("azure AGW update", rg + "/" + gw, e);
            }
            log.error("{} unexpected failure at {}/{}: {}", CTX, rg, gw, e.getMessage(), e);
            throw new PermanentAgentException("DEPLOY_AZURE_FAILED",
                    CTX + " deployment failed at " + rg + "/" + gw + ": " + e.getMessage(), e);
        }

        return DeploymentResult.of(agwId, toResultJson(sslCertName, secretId));
    }

    private void validateScope(AzureAppGatewayScope scope) {
        if (scope.subscriptionId() == null || scope.subscriptionId().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.subscriptionId is required");
        }
        if (scope.resourceGroup() == null || scope.resourceGroup().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.resourceGroup is required");
        }
        if (scope.appGateway() == null || scope.appGateway().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.appGateway is required");
        }
        if (scope.listeners() == null || scope.listeners().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.listeners must be a non-empty array");
        }
        if (scope.keyVaultUri() == null || scope.keyVaultUri().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.keyVaultUri is required");
        }
    }

    private String importToKeyVault(String keyVaultUri,
                                    String certName,
                                    byte[] pfxBytes,
                                    TokenCredential azureCredential) {
        try {
            CertificateClient certClient = new CertificateClientBuilder()
                    .vaultUrl(keyVaultUri)
                    .credential(azureCredential)
                    .buildClient();
            ImportCertificateOptions options = new ImportCertificateOptions(certName, pfxBytes);
            options.setEnabled(true);
            // Explicitly mark as PKCS12 so KV doesn't try to PEM-parse the binary payload, and
            // AGW gets a valid PFX back when it fetches the secret.
            options.setPolicy(new CertificatePolicy("Self", "CN=" + certName)
                    .setContentType(CertificateContentType.PKCS12));
            KeyVaultCertificateWithPolicy imported = certClient.importCertificate(options);
            String secretId = imported.getSecretId();
            if (secretId == null || secretId.isBlank()) {
                throw new PermanentAgentException("DEPLOY_RESULT_NULL_RESOURCE_ID",
                        "Key Vault import returned empty secretId for AGW");
            }
            return secretId;
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure KV import (AGW)", certName, e);
            }
            if (e instanceof HttpResponseException h && AzureErrorClassifier.isPermissionDenied(h)) {
                throw new PermanentAgentException(AzureErrorClassifier.PERMISSION_DENIED,
                        "Key Vault import denied for App Gateway: " + e.getMessage(), e);
            }
            throw new PermanentAgentException("DEPLOY_AZURE_KV_IMPORT_FAILED",
                    "Failed to import cert into Key Vault for App Gateway: " + e.getMessage(), e);
        }
    }

    private AzureAppGatewayScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AzureAppGatewayScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AzureAppGatewayTargets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new AzureAppGatewayTargets(null, List.of());
        }
        try {
            return objectMapper.readValue(json, AzureAppGatewayTargets.class);
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

    private String requireDomain(String rawDomain, String certXref) {
        String domain = CertificateIdentityUtils.normaliseDomain(rawDomain);
        if (domain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                    "CERT_DEPLOYMENT message missing required domain for xref=" + certXref);
        }
        return domain;
    }

    /**
     * Read the prior {@code result.certificateName} (the AGW SSL cert resource name used last
     * rotation) so the next rotation locks onto the same name and avoids orphaning the AGW
     * SSL cert resource. Returns null on first deploy or if the configJson is empty/unparseable.
     */
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

    private String toResultJson(String certName, String secretId) {
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("certificateName", certName);
            root.put("keyVaultSecretId", secretId);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"certificateName\":\"" + (certName == null ? "" : certName) + "\"}";
        }
    }

    /**
     * Recursively flattens a {@link ManagementError} (Azure's structured error payload) into a
     * single human-readable string. Walks {@code details[]} so we don't lose nested errors like
     * {@code ApplicationGatewayCustomError} or {@code KeyVaultAccessForbidden} that ARM wraps
     * inside the top-level error.
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

    /**
     * Best-effort read of the HTTP response body for diagnostic logging. The Azure SDK consumes
     * the response stream eagerly during error mapping, so the body may already be drained — in
     * that case, fall back to the exception message.
     */
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
