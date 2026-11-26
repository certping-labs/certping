// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.certmanagement.credential.EmulatorCredential;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Azure Key Vault-backed {@link AgentSecretStore}. Handles are Azure KV secret URIs
 * ({@code https://<vault>.vault.azure.net/secrets/<name>}, optionally suffixed with a version id).
 *
 * <p>Only activated when {@code certping.agent-secret-store.provider=AZURE_KV}. Holds the name
 * validation, deterministic name generation, and the "only touch our own vault" guard on the
 * delete path.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "certping.agent-secret-store.provider", havingValue = "AZURE_KV",
        matchIfMissing = true)
public class AzureKeyVaultAgentDriver implements AgentSecretStore {

    private static final Pattern SECRET_NAME_PATTERN = Pattern.compile("^[a-z0-9-]{1,127}$");
    private static final Pattern KV_URI_PATTERN = Pattern.compile(
            "^https://([a-zA-Z0-9-]+)\\.vault\\.azure\\.net/secrets/([a-zA-Z0-9-]+)(/[a-zA-Z0-9]+)?$");

    private final AgentSecretStoreProperties.AzureKv azureProps;

    private SecretClient client;
    private String normalizedVaultUrl;
    private String vaultHost;

    public AzureKeyVaultAgentDriver(AgentSecretStoreProperties properties) {
        this.azureProps = properties.getAzureKv();
    }

    @PostConstruct
    void initialize() {
        if (azureProps.getVaultUri() == null || azureProps.getVaultUri().isBlank()) {
            log.info("AzureKeyVaultAgentDriver: certping.agent-secret-store.azure-kv.vault-uri unset — "
                    + "driver constructed but not usable until it is configured");
            return;
        }
        TokenCredential credential = azureProps.isUseEmulatorCredential()
                ? new EmulatorCredential()
                : new DefaultAzureCredentialBuilder().build();

        normalizedVaultUrl = stripTrailingSlash(azureProps.getVaultUri());
        vaultHost = URI.create(normalizedVaultUrl).getHost();

        SecretClientBuilder builder = new SecretClientBuilder()
                .vaultUrl(normalizedVaultUrl)
                .credential(credential);
        if (azureProps.isUseEmulatorCredential() || azureProps.isDisableChallengeResourceVerification()) {
            builder.disableChallengeResourceVerification();
        }
        client = builder.buildClient();
        log.info("AzureKeyVaultAgentDriver ready: vault={}", normalizedVaultUrl);
    }

    @Override
    public AgentSecretStoreProvider provider() {
        return AgentSecretStoreProvider.AZURE_KV;
    }

    @Override
    public boolean isReady() {
        return client != null;
    }

    @Override
    public String create(String name, String value) {
        requireConfigured();
        requireValidName(name);
        client.setSecret(name, value);
        String handle = normalizedVaultUrl + "/secrets/" + name;
        log.info("Wrote agent KV secret: name={}", name);
        return handle;
    }

    @Override
    public String read(String handle) {
        requireConfigured();
        requireValidHandle(handle);
        try {
            return client.getSecret(secretNameFromHandle(handle)).getValue();
        } catch (ResourceNotFoundException e) {
            throw new com.certmanagement.exception.ResourceNotFoundException(
                    "Agent KV secret not found at handle: " + handle);
        }
    }

    @Override
    public String update(String handle, String value) {
        requireConfigured();
        requireValidHandle(handle);
        if (!isOwnedByThisCertManager(handle)) {
            throw new BadRequestException(
                    "Refusing to update secret at foreign KV handle: " + handle);
        }
        String name = secretNameFromHandle(handle);
        client.setSecret(name, value);
        return normalizedVaultUrl + "/secrets/" + name;
    }

    @Override
    public void deleteIfOwned(String handle) {
        if (handle == null || handle.isBlank() || client == null) {
            return;
        }
        if (!isOwnedByThisCertManager(handle)) {
            return;
        }
        String name = secretNameFromHandle(handle);
        try {
            client.beginDeleteSecret(name).waitForCompletion();
            log.info("Deleted agent KV secret: name={}", name);
        } catch (ResourceNotFoundException ignored) {
            log.debug("Agent KV secret already gone: name={}", name);
            return;
        }
        try {
            client.purgeDeletedSecret(name);
        } catch (Exception ex) {
            log.warn("Could not purge agent KV secret (soft-delete protection may be off): name={}, reason={}",
                    name, ex.getMessage());
        }
    }

    @Override
    public boolean isOwnedByThisCertManager(String handle) {
        if (handle == null || vaultHost == null) {
            return false;
        }
        Matcher m = KV_URI_PATTERN.matcher(handle);
        if (!m.matches()) {
            return false;
        }
        String handleHost;
        try {
            handleHost = URI.create(handle).getHost();
        } catch (IllegalArgumentException ex) {
            return false;
        }
        return vaultHost.equalsIgnoreCase(handleHost);
    }

    @Override
    public boolean isAgentCertificateHandle(String handle, String certificateXref) {
        return certificateXref != null
                && isOwnedByThisCertManager(handle)
                && certificateXref.equals(secretNameFromHandle(handle));
    }

    @Override
    public String handleFor(String name) {
        requireConfigured();
        requireValidName(name);
        return normalizedVaultUrl + "/secrets/" + name;
    }

    private void requireConfigured() {
        if (client == null) {
            throw new IllegalStateException(
                    "AzureKeyVaultAgentDriver is not configured — set certping.agent-secret-store.azure-kv.vault-uri");
        }
    }

    private static void requireValidName(String name) {
        if (name == null || !SECRET_NAME_PATTERN.matcher(name).matches()) {
            throw new BadRequestException(
                    "Invalid KV secret name (must match " + SECRET_NAME_PATTERN.pattern() + "): " + name);
        }
    }

    private static void requireValidHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            throw new BadRequestException("Agent KV handle is null or blank");
        }
        if (!KV_URI_PATTERN.matcher(handle).matches()) {
            throw new BadRequestException("Handle is not a valid Azure KV secret URI: " + handle);
        }
    }

    private static String secretNameFromHandle(String handle) {
        Matcher m = KV_URI_PATTERN.matcher(handle);
        if (!m.matches()) {
            throw new BadRequestException("Handle is not a valid Azure KV secret URI: " + handle);
        }
        return m.group(2);
    }

    private static String stripTrailingSlash(String uri) {
        return uri.endsWith("/") ? uri.substring(0, uri.length() - 1) : uri;
    }
}
