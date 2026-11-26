// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.identity.WorkloadIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.certping.agent.credential.EmulatorCredential;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreDriver;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProperties.AzureAuthMode;
import com.certping.agent.secrets.SecretStoreProperties.AzureKvProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Slf4j
@Component
@ConditionalOnProperty(name = "agent.secret-store.provider", havingValue = "AZURE_KV", matchIfMissing = true)
public class AzureSecretStoreDriver implements SecretStoreDriver {

    private static final Pattern HANDLE_PATTERN = Pattern.compile(
            "^https://[a-zA-Z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[A-Za-z0-9]+)?$");
    private static final Pattern MHSM_HANDLE_PATTERN = Pattern.compile(
            "^https://[a-zA-Z0-9-]+\\.managedhsm\\.azure\\.net/secrets/[A-Za-z0-9-]+(/[A-Za-z0-9]+)?$");

    /** Common subset across all providers — safe to migrate a customer without name rewrites. */
    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,127}$");

    private final AzureKvProperties properties;
    private final String activeProfile;

    private TokenCredential credential;
    private boolean disableChallengeResourceVerification;
    private String ownVaultHost;
    private String ownVaultUrlNormalised;

    private final ConcurrentHashMap<String, SecretClient> clientCache = new ConcurrentHashMap<>();

    public AzureSecretStoreDriver(SecretStoreProperties properties,
                                  @Value("${spring.profiles.active:${SPRING_PROFILES_ACTIVE:}}") String activeProfile) {
        this.properties = properties.getAzureKv();
        this.activeProfile = activeProfile == null ? "" : activeProfile;
    }

    @PostConstruct
    void init() {
        this.credential = buildCredential(properties.getAuthMode());
        this.disableChallengeResourceVerification =
                properties.getAuthMode() == AzureAuthMode.EMULATOR
                        || properties.isDisableChallengeResourceVerification();

        String vault = properties.getVaultUri();
        if (vault == null || vault.isBlank()) {
            throw new IllegalStateException(
                    "agent.secret-store.azure-kv.vault-uri is required when provider=AZURE_KV");
        }
        this.ownVaultUrlNormalised = vault.endsWith("/") ? vault.substring(0, vault.length() - 1) : vault;
        try {
            this.ownVaultHost = URI.create(this.ownVaultUrlNormalised).getHost();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "agent.secret-store.azure-kv.vault-uri is not a valid URI: " + vault, e);
        }
        log.info("AzureSecretStoreDriver ready: vault={}, authMode={}",
                ownVaultUrlNormalised, properties.getAuthMode());
    }

    @Override
    public SecretStoreProvider provider() {
        return SecretStoreProvider.AZURE_KV;
    }

    @Override
    public boolean parsesHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            return false;
        }
        return HANDLE_PATTERN.matcher(handle).matches()
                || MHSM_HANDLE_PATTERN.matcher(handle).matches();
    }

    @Override
    public void assertValidName(String name) {
        if (name == null || !NAME_PATTERN.matcher(name).matches()) {
            throw new PermanentAgentException("SECRET_STORE_NAME_INVALID",
                    "Secret name must match [A-Za-z0-9_-]{1,127}, got: "
                            + (name == null ? "null" : "'" + name + "'"));
        }
    }

    @Override
    public boolean isOwnedByThisAgent(String handle) {
        if (!parsesHandle(handle)) {
            return false;
        }
        try {
            String host = URI.create(handle).getHost();
            return host != null && host.equalsIgnoreCase(ownVaultHost);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String handleFor(String name) {
        assertValidName(name);
        return ownVaultUrlNormalised + "/secrets/" + name;
    }

    @Override
    public String read(String handle) {
        requireHandle(handle);
        String secretName = extractSecretName(handle);
        SecretClient client = clientFor(handle);

        try {
            return client.getSecret(secretName).getValue();
        } catch (ResourceNotFoundException e) {
            throw new PermanentAgentException("KV_SECRET_NOT_FOUND",
                    "Secret not found at handle: " + handle, e);
        } catch (HttpResponseException e) {
            throw classifyRead(handle, e);
        } catch (Exception e) {
            throw classifyRead(handle, e);
        }
    }

    @Override
    public String create(String name, String value) {
        assertValidName(name);
        try {
            return doCreateOnOwnStore(name, value);
        } catch (HttpResponseException e) {
            // Soft-deleted secret with same name blocks re-creation; recover then retry once.
            if (isObjectDeletedButRecoverable(e)) {
                log.info("Secret '{}' is soft-deleted; recovering before re-write", name);
                try {
                    ownStoreClient().beginRecoverDeletedSecret(name).waitForCompletion();
                    return doCreateOnOwnStore(name, value);
                } catch (Exception recoverEx) {
                    throw new TransientAgentException("KV_WRITE_FAILED",
                            "Failed to recover soft-deleted secret '" + name + "': "
                                    + recoverEx.getMessage(), recoverEx);
                }
            }
            throw classifyWrite(name, e);
        } catch (Exception e) {
            throw classifyWrite(name, e);
        }
    }

    @Override
    public String update(String handle, String value) {
        requireHandle(handle);
        String secretName = extractSecretName(handle);
        SecretClient client = clientFor(handle);

        try {
            KeyVaultSecret stored = client.setSecret(secretName, value);
            if (stored != null && stored.getId() != null && !stored.getId().isBlank()) {
                return stored.getId();
            }
            return handle;
        } catch (HttpResponseException e) {
            throw classifyWriteAtHandle(handle, e);
        } catch (Exception e) {
            throw classifyWriteAtHandle(handle, e);
        }
    }

    @Override
    public void delete(String handle) {
        requireHandle(handle);
        String secretName = extractSecretName(handle);
        SecretClient client = clientFor(handle);

        try {
            client.beginDeleteSecret(secretName).waitForCompletion();

            // Own-store deletes purge the tombstone; foreign-vault deletes leave it (customer's recovery policy).
            if (isOwnedByThisAgent(handle)) {
                try {
                    client.purgeDeletedSecret(secretName);
                } catch (ResourceNotFoundException tombstoneAlreadyPurged) {
                    log.debug("Tombstone for '{}' already purged", secretName);
                } catch (Exception purgeErr) {
                    log.warn("Failed to purge '{}' after delete: {}", secretName, purgeErr.getMessage());
                }
            }
        } catch (ResourceNotFoundException e) {
            log.info("Secret '{}' already absent at {} — treating as success",
                    secretName, URI.create(handle).getHost());
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("azure KV secret delete", handle, e);
            }
            throw new TransientAgentException("KV_DELETE_FAILED",
                    "Failed to delete secret at " + handle + ": " + e.getMessage(), e);
        }
    }

    private TokenCredential buildCredential(AzureAuthMode mode) {
        switch (mode) {
            case WORKLOAD_IDENTITY -> {
                WorkloadIdentityCredentialBuilder b = new WorkloadIdentityCredentialBuilder();
                if (properties.getTenantId() != null && !properties.getTenantId().isBlank()) {
                    b.tenantId(properties.getTenantId());
                }
                if (properties.getClientId() != null && !properties.getClientId().isBlank()) {
                    b.clientId(properties.getClientId());
                }
                if (properties.getFederatedTokenFile() != null && !properties.getFederatedTokenFile().isBlank()) {
                    b.tokenFilePath(properties.getFederatedTokenFile());
                }
                return b.build();
            }
            case CLIENT_SECRET -> {
                requireAuthField("tenant-id", properties.getTenantId());
                requireAuthField("client-id", properties.getClientId());
                requireAuthField("client-secret", properties.getClientSecret());
                return new ClientSecretCredentialBuilder()
                        .tenantId(properties.getTenantId())
                        .clientId(properties.getClientId())
                        .clientSecret(properties.getClientSecret())
                        .build();
            }
            case CLIENT_CERTIFICATE -> {
                requireAuthField("tenant-id", properties.getTenantId());
                requireAuthField("client-id", properties.getClientId());
                requireAuthField("client-certificate-path", properties.getClientCertificatePath());
                return new ClientCertificateCredentialBuilder()
                        .tenantId(properties.getTenantId())
                        .clientId(properties.getClientId())
                        .pemCertificate(properties.getClientCertificatePath())
                        .build();
            }
            case EMULATOR -> {
                if (!"local".equalsIgnoreCase(activeProfile)) {
                    throw new IllegalStateException(
                            "auth-mode=EMULATOR is only valid under the 'local' Spring profile");
                }
                return new EmulatorCredential();
            }
            case DEFAULT -> {
                log.warn("Using DefaultAzureCredential chain — prefer explicit auth-mode in production");
                return new DefaultAzureCredentialBuilder().build();
            }
        }
        throw new IllegalStateException("Unhandled AzureAuthMode: " + mode);
    }

    private static void requireAuthField(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "agent.secret-store.azure-kv." + name + " is required for the configured auth-mode");
        }
    }

    private SecretClient clientFor(String handle) {
        String hostKey = hostOf(handle);
        String scheme = URI.create(handle).getScheme();
        return clientCache.computeIfAbsent(hostKey, k -> {
            SecretClientBuilder b = new SecretClientBuilder()
                    .vaultUrl(scheme + "://" + hostKey)
                    .credential(credential);
            if (disableChallengeResourceVerification) {
                b.disableChallengeResourceVerification();
            }
            return b.buildClient();
        });
    }

    private SecretClient ownStoreClient() {
        return clientCache.computeIfAbsent(ownVaultHost, k -> {
            SecretClientBuilder b = new SecretClientBuilder()
                    .vaultUrl(ownVaultUrlNormalised)
                    .credential(credential);
            if (disableChallengeResourceVerification) {
                b.disableChallengeResourceVerification();
            }
            return b.buildClient();
        });
    }

    private String doCreateOnOwnStore(String secretName, String value) {
        KeyVaultSecret stored = ownStoreClient().setSecret(new KeyVaultSecret(secretName, value));
        if (stored != null && stored.getId() != null && !stored.getId().isBlank()) {
            return stored.getId();
        }
        return ownVaultUrlNormalised + "/secrets/" + secretName;
    }

    private void requireHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            throw new PermanentAgentException("KV_URI_BLANK", "KV handle is null or blank");
        }
    }

    private static String extractSecretName(String handle) {
        String[] parts;
        try {
            parts = URI.create(handle).getPath().split("/secrets/", 2);
        } catch (Exception e) {
            throw new PermanentAgentException("KV_URI_INVALID",
                    "Handle is not a valid URI: " + handle, e);
        }
        if (parts.length < 2 || parts[1].isBlank()) {
            throw new PermanentAgentException("KV_URI_INVALID",
                    "Handle does not contain /secrets/{name}: " + handle);
        }
        return parts[1].split("/")[0];
    }

    private static String hostOf(String handle) {
        String authority;
        try {
            authority = URI.create(handle).getAuthority();
        } catch (Exception e) {
            throw new PermanentAgentException("KV_URI_INVALID", "Handle is not a valid URI: " + handle, e);
        }
        if (authority == null || authority.isBlank()) {
            throw new PermanentAgentException("KV_URI_INVALID", "Handle missing authority: " + handle);
        }
        return authority;
    }

    private static boolean isObjectDeletedButRecoverable(Exception e) {
        String msg = e.getMessage();
        return msg != null && msg.contains("ObjectIsDeletedButRecoverable");
    }

    private RuntimeException classifyRead(String handle, Exception e) {
        if (e instanceof HttpResponseException hre) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(hre, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                return rl.get().toRetryable("azure KV secret read", handle, e);
            }
            if (hre.getResponse() != null && hre.getResponse().getStatusCode() == 403) {
                return new PermanentAgentException("KV_ACCESS_DENIED",
                        "Access denied to KV secret: " + handle, e);
            }
            return new TransientAgentException("KV_HTTP_ERROR",
                    "HTTP error reading KV secret: " + e.getMessage(), e);
        }
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("azure KV secret read", handle, e);
        }
        return new TransientAgentException("KV_READ_FAILED",
                "Failed to read secret from " + handle + ": " + e.getMessage(), e);
    }

    private RuntimeException classifyWrite(String name, Exception e) {
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("azure KV secret write", name, e);
        }
        return new TransientAgentException("KV_WRITE_FAILED",
                "Failed to store secret '" + name + "': " + e.getMessage(), e);
    }

    private RuntimeException classifyWriteAtHandle(String handle, Exception e) {
        if (e instanceof HttpResponseException hre) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAzure(hre, "KV_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                return rl.get().toRetryable("azure KV secret write", handle, e);
            }
            if (hre.getResponse() != null && hre.getResponse().getStatusCode() == 403) {
                return new PermanentAgentException("KV_ACCESS_DENIED",
                        "Access denied writing KV secret: " + handle, e);
            }
            return new TransientAgentException("KV_HTTP_ERROR",
                    "HTTP error writing KV secret: " + e.getMessage(), e);
        }
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.classify(e, "KV_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("azure KV secret write", handle, e);
        }
        return new TransientAgentException("KV_WRITE_FAILED",
                "Failed to write secret to " + handle + ": " + e.getMessage(), e);
    }
}
