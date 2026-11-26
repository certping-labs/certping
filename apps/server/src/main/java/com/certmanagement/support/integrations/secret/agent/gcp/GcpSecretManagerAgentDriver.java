// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.gcp;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties.GcpAuthMode;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties.GcpSecretManager;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.AlreadyExistsException;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.FailedPreconditionException;
import com.google.api.gax.rpc.NotFoundException;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.AddSecretVersionRequest;
import com.google.cloud.secretmanager.v1.CreateSecretRequest;
import com.google.cloud.secretmanager.v1.ProjectName;
import com.google.cloud.secretmanager.v1.Replication;
import com.google.cloud.secretmanager.v1.Secret;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretName;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.cloud.secretmanager.v1.SecretVersion;
import com.google.protobuf.ByteString;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GCP Secret Manager-backed {@link AgentSecretStore}. Handles are versioned resource paths
 * ({@code projects/<project>/secrets/<name>/versions/<latest|N>}). The project segment is the
 * project id in handles built here ({@link #handleFor}) and the project NUMBER in names the API
 * returns, which is what the agent persists for certificates; both are recognised as this
 * store's when {@code project-number} is configured.
 *
 * <p>Only activated when {@code certping.agent-secret-store.provider=GCP_SECRET_MANAGER}.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "certping.agent-secret-store.provider", havingValue = "GCP_SECRET_MANAGER")
public class GcpSecretManagerAgentDriver implements AgentSecretStore {

    private static final Pattern HANDLE_PATTERN = Pattern.compile(
            "^projects/([a-z0-9-]+)/secrets/([A-Za-z0-9_-]{1,255})/versions/(latest|\\d+)$");
    private static final Pattern SECRET_NAME_ONLY = Pattern.compile(
            "^projects/([a-z0-9-]+)/secrets/([A-Za-z0-9_-]{1,255})$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,127}$");
    private static final Pattern PROJECT_NUMBER_PATTERN = Pattern.compile("^\\d{1,30}$");

    private final GcpSecretManager properties;
    private final String activeProfile;

    private SecretManagerServiceClient client;
    private String projectId;
    /** Null when not configured: then only {@link #projectId} identifies this store's project. */
    private String projectNumber;
    private String ownSecretPrefix;

    public GcpSecretManagerAgentDriver(AgentSecretStoreProperties properties,
                                       org.springframework.core.env.Environment env) {
        this.properties = properties.getGcpSecretManager();
        String[] profiles = env.getActiveProfiles();
        this.activeProfile = profiles.length == 0 ? "" : profiles[0];
    }

    @PostConstruct
    void init() {
        if (properties.getProjectId() == null || properties.getProjectId().isBlank()) {
            throw new IllegalStateException(
                    "certping.agent-secret-store.gcp-secret-manager.project-id is required "
                            + "when provider=GCP_SECRET_MANAGER");
        }
        this.projectId = properties.getProjectId();
        this.projectNumber = normalizeProjectNumber(properties.getProjectNumber());
        this.ownSecretPrefix = normalizePrefix(properties.getOwnStoreSecretPrefix());
        try {
            GoogleCredentials credentials = buildCredentials(properties.getAuthMode());
            SecretManagerServiceSettings settings = SecretManagerServiceSettings.newBuilder()
                    .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                    .build();
            this.client = SecretManagerServiceClient.create(settings);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to bootstrap GCP Secret Manager client: " + e.getMessage(), e);
        }
        log.info("GcpSecretManagerAgentDriver ready: project={}, projectNumber={}, authMode={}, prefix={}",
                projectId, projectNumber, properties.getAuthMode(), ownSecretPrefix);
    }

    @PreDestroy
    void shutdown() {
        if (client != null) {
            try { client.close(); } catch (Exception ignored) { }
        }
    }

    @Override
    public AgentSecretStoreProvider provider() {
        return AgentSecretStoreProvider.GCP_SECRET_MANAGER;
    }

    @Override
    public String create(String name, String value) {
        requireValidName(name);
        String secretId = ownSecretPrefix + name;
        String parent = ProjectName.of(projectId).toString();
        try {
            Secret secret = Secret.newBuilder()
                    .setReplication(Replication.newBuilder()
                            .setAutomatic(Replication.Automatic.newBuilder().build())
                            .build())
                    .build();
            try {
                client.createSecret(CreateSecretRequest.newBuilder()
                        .setParent(parent)
                        .setSecretId(secretId)
                        .setSecret(secret)
                        .build());
            } catch (AlreadyExistsException ignored) {
                // Parent already exists — go straight to AddSecretVersion.
            }
            SecretName secretName = SecretName.of(projectId, secretId);
            SecretVersion version = client.addSecretVersion(AddSecretVersionRequest.newBuilder()
                    .setParent(secretName.toString())
                    .setPayload(SecretPayload.newBuilder()
                            .setData(ByteString.copyFromUtf8(value))
                            .build())
                    .build());
            return version.getName();
        } catch (ApiException e) {
            throw new IllegalStateException("Failed to create GCP secret '" + name + "': " + e.getMessage(), e);
        }
    }

    @Override
    public String read(String handle) {
        requireValidHandle(handle);
        try {
            AccessSecretVersionResponse resp = client.accessSecretVersion(handle);
            return resp.getPayload().getData().toStringUtf8();
        } catch (NotFoundException e) {
            throw new ResourceNotFoundException("Agent secret not found at handle: " + handle);
        } catch (FailedPreconditionException e) {
            // Secret Manager's answer for a DESTROYED or DISABLED version: the value is not coming back.
            throw new AgentSecretGoneException("GCP secret version is destroyed or disabled: " + handle, e);
        } catch (ApiException e) {
            throw new IllegalStateException("Failed to read GCP secret at " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String update(String handle, String value) {
        requireValidHandle(handle);
        if (!isOwnedByThisCertManager(handle)) {
            throw new BadRequestException(
                    "Refusing to update secret at foreign GCP handle: " + handle);
        }
        String parent = parentSecretName(handle);
        try {
            SecretVersion version = client.addSecretVersion(AddSecretVersionRequest.newBuilder()
                    .setParent(parent)
                    .setPayload(SecretPayload.newBuilder()
                            .setData(ByteString.copyFromUtf8(value))
                            .build())
                    .build());
            return version.getName();
        } catch (NotFoundException e) {
            throw new ResourceNotFoundException("Agent secret not found at handle: " + handle);
        } catch (ApiException e) {
            throw new IllegalStateException("Failed to update GCP secret at " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void deleteIfOwned(String handle) {
        if (handle == null || handle.isBlank() || client == null) {
            return;
        }
        if (!isOwnedByThisCertManager(handle)) {
            return;
        }
        String parent = parentSecretName(handle);
        try {
            client.deleteSecret(parent);
            log.info("Deleted agent GCP secret: handle={}", handle);
        } catch (NotFoundException e) {
            log.debug("GCP secret already gone: handle={}", handle);
        } catch (ApiException e) {
            log.warn("GCP delete failed for handle={}: {}", handle, e.getMessage());
        }
    }

    @Override
    public boolean isOwnedByThisCertManager(String handle) {
        Matcher m = matchOrNull(handle);
        if (m == null) {
            return false;
        }
        return isOwnProject(m.group(1)) && m.group(2).startsWith(ownSecretPrefix);
    }

    /** Versioned handles only: the agent persists a version name, so a bare secret path is not one of its handles. */
    @Override
    public boolean isAgentCertificateHandle(String handle, String certificateXref) {
        if (handle == null || certificateXref == null) {
            return false;
        }
        Matcher m = HANDLE_PATTERN.matcher(handle);
        return m.matches()
                && isOwnProject(m.group(1))
                && m.group(2).equals(ownSecretPrefix + certificateXref);
    }

    @Override
    public String handleFor(String name) {
        requireValidName(name);
        return "projects/" + projectId + "/secrets/" + ownSecretPrefix + name + "/versions/latest";
    }

    private GoogleCredentials buildCredentials(GcpAuthMode mode) throws Exception {
        switch (mode) {
            case WORKLOAD_IDENTITY_FEDERATION -> {
                requireAuthField("credential-config-file", properties.getCredentialConfigFile());
                return GoogleCredentials.fromStream(new FileInputStream(properties.getCredentialConfigFile()))
                        .createScoped(Collections.singleton("https://www.googleapis.com/auth/cloud-platform"));
            }
            case ADC -> {
                return GoogleCredentials.getApplicationDefault()
                        .createScoped(Collections.singleton("https://www.googleapis.com/auth/cloud-platform"));
            }
            case SA_JSON -> {
                if (!"local".equalsIgnoreCase(activeProfile)) {
                    throw new IllegalStateException(
                            "auth-mode=SA_JSON is only valid under the 'local' Spring profile");
                }
                requireAuthField("sa-json-file", properties.getSaJsonFile());
                return GoogleCredentials.fromStream(new FileInputStream(properties.getSaJsonFile()))
                        .createScoped(Collections.singleton("https://www.googleapis.com/auth/cloud-platform"));
            }
        }
        throw new IllegalStateException("Unhandled GcpAuthMode: " + mode);
    }

    private static void requireAuthField(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "certping.agent-secret-store.gcp-secret-manager." + name
                            + " is required for the configured auth-mode");
        }
    }

    private static void requireValidName(String name) {
        if (name == null || !NAME_PATTERN.matcher(name).matches()) {
            throw new BadRequestException(
                    "Invalid GCP secret name (must match " + NAME_PATTERN.pattern() + "): " + name);
        }
    }

    private static void requireValidHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            throw new BadRequestException("GCP secret handle is null or blank");
        }
        if (!HANDLE_PATTERN.matcher(handle).matches()) {
            throw new BadRequestException("Handle is not a valid GCP Secret Manager resource path: " + handle);
        }
    }

    /** This store's project, by id or (when configured) by number; exact match only. */
    private boolean isOwnProject(String projectSegment) {
        return projectSegment.equals(projectId)
                || (projectNumber != null && projectSegment.equals(projectNumber));
    }

    private static String parentSecretName(String handle) {
        Matcher m = matchOrNull(handle);
        if (m == null) {
            throw new BadRequestException("Handle is not a valid GCP Secret Manager resource path: " + handle);
        }
        return "projects/" + m.group(1) + "/secrets/" + m.group(2);
    }

    private static Matcher matchOrNull(String handle) {
        if (handle == null) return null;
        Matcher m = HANDLE_PATTERN.matcher(handle);
        if (m.matches()) return m;
        Matcher parent = SECRET_NAME_ONLY.matcher(handle);
        return parent.matches() ? parent : null;
    }

    private static String normalizeProjectNumber(String configured) {
        if (configured == null || configured.isBlank()) {
            return null;
        }
        if (!PROJECT_NUMBER_PATTERN.matcher(configured).matches()) {
            throw new IllegalStateException(
                    "certping.agent-secret-store.gcp-secret-manager.project-number must be numeric");
        }
        return configured;
    }

    private static String normalizePrefix(String prefix) {
        return prefix == null || prefix.isBlank() ? "" : prefix;
    }
}
