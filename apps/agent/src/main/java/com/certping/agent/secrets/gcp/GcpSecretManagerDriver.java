// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.gcp;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreDriver;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProperties.GcpAuthMode;
import com.certping.agent.secrets.SecretStoreProperties.GcpSecretManagerProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.AlreadyExistsException;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.NotFoundException;
import com.google.api.gax.rpc.PermissionDeniedException;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.util.Collections;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
@ConditionalOnProperty(name = "agent.secret-store.provider", havingValue = "GCP_SECRET_MANAGER")
public class GcpSecretManagerDriver implements SecretStoreDriver {

    private static final Pattern HANDLE_PATTERN = Pattern.compile(
            "^projects/([a-z0-9-]+)/secrets/([A-Za-z0-9_-]{1,255})/versions/(latest|\\d+)$");

    private static final Pattern SECRET_NAME_ONLY = Pattern.compile(
            "^projects/([a-z0-9-]+)/secrets/([A-Za-z0-9_-]{1,255})$");

    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,127}$");

    private final GcpSecretManagerProperties properties;
    private final String activeProfile;

    private SecretManagerServiceClient client;
    private String projectId;
    private String ownSecretPrefix;

    @Autowired
    public GcpSecretManagerDriver(SecretStoreProperties properties,
                                  @Value("${spring.profiles.active:${SPRING_PROFILES_ACTIVE:}}") String activeProfile) {
        this.properties = properties.getGcpSecretManager();
        this.activeProfile = activeProfile == null ? "" : activeProfile;
    }

    // Test seam.
    GcpSecretManagerDriver(SecretStoreProperties properties, String activeProfile,
                           SecretManagerServiceClient injectedClient) {
        this.properties = properties.getGcpSecretManager();
        this.activeProfile = activeProfile == null ? "" : activeProfile;
        this.client = injectedClient;
        this.projectId = this.properties.getProjectId();
        this.ownSecretPrefix = normalizePrefix(this.properties.getOwnStoreSecretPrefix());
    }

    @PostConstruct
    void init() {
        if (client != null) {
            return;
        }
        if (properties.getProjectId() == null || properties.getProjectId().isBlank()) {
            throw new IllegalStateException(
                    "agent.secret-store.gcp-secret-manager.project-id is required when provider=GCP_SECRET_MANAGER");
        }
        this.projectId = properties.getProjectId();
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
        log.info("GcpSecretManagerDriver ready: project={}, authMode={}, prefix={}",
                projectId, properties.getAuthMode(), ownSecretPrefix);
    }

    @PreDestroy
    void shutdown() {
        if (client != null) {
            try { client.close(); } catch (Exception ignored) { }
        }
    }

    @Override
    public SecretStoreProvider provider() {
        return SecretStoreProvider.GCP_SECRET_MANAGER;
    }

    @Override
    public boolean parsesHandle(String handle) {
        return handle != null && !handle.isBlank() && HANDLE_PATTERN.matcher(handle).matches();
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
        Matcher m = matchOrNull(handle);
        if (m == null) {
            return false;
        }
        return m.group(1).equals(projectId) && m.group(2).startsWith(ownSecretPrefix);
    }

    @Override
    public String handleFor(String name) {
        assertValidName(name);
        return "projects/" + projectId + "/secrets/" + ownSecretPrefix + name + "/versions/latest";
    }

    @Override
    public String read(String handle) {
        requireHandle(handle);
        try {
            AccessSecretVersionResponse resp = client.accessSecretVersion(handle);
            return resp.getPayload().getData().toStringUtf8();
        } catch (NotFoundException e) {
            throw new PermanentAgentException("SM_SECRET_NOT_FOUND",
                    "Secret not found at handle: " + handle, e);
        } catch (PermissionDeniedException e) {
            throw new PermanentAgentException("SM_ACCESS_DENIED",
                    "Access denied reading secret: " + handle, e);
        } catch (ApiException e) {
            throw classifyRead(handle, e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_READ_FAILED",
                    "Failed to read secret from " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String create(String name, String value) {
        assertValidName(name);
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
        } catch (PermissionDeniedException e) {
            throw new PermanentAgentException("SM_ACCESS_DENIED",
                    "Access denied creating secret '" + name + "'", e);
        } catch (ApiException e) {
            throw classifyWrite(name, e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_WRITE_FAILED",
                    "Failed to create secret '" + name + "': " + e.getMessage(), e);
        }
    }

    @Override
    public String update(String handle, String value) {
        requireHandle(handle);
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
            throw new PermanentAgentException("SM_SECRET_NOT_FOUND",
                    "Secret not found at handle: " + handle, e);
        } catch (PermissionDeniedException e) {
            throw new PermanentAgentException("SM_ACCESS_DENIED",
                    "Access denied writing secret: " + handle, e);
        } catch (ApiException e) {
            throw classifyWrite(handle, e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_WRITE_FAILED",
                    "Failed to write secret to " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void delete(String handle) {
        requireHandle(handle);
        if (!isOwnedByThisAgent(handle)) {
            // GCP has no soft-delete window — refusing hard-delete on foreign
            // handles matches Azure's "leave customer tombstones in place" stance.
            log.warn("Refusing to delete foreign GCP secret handle {} — GCP has no soft-delete window", handle);
            return;
        }
        String parent = parentSecretName(handle);
        try {
            client.deleteSecret(parent);
        } catch (NotFoundException e) {
            log.info("Secret already absent at {} — treating as success", handle);
        } catch (ApiException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromGcp(e, "SM_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp sm secret delete", handle, e);
            }
            throw new TransientAgentException("SM_DELETE_FAILED",
                    "Failed to delete secret at " + handle + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_DELETE_FAILED",
                    "Failed to delete secret at " + handle + ": " + e.getMessage(), e);
        }
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
                    "agent.secret-store.gcp-secret-manager." + name + " is required for the configured auth-mode");
        }
    }

    private void requireHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            throw new PermanentAgentException("SM_HANDLE_BLANK", "Secret handle is null or blank");
        }
        if (!parsesHandle(handle)) {
            throw new PermanentAgentException("SM_HANDLE_INVALID",
                    "Handle is not a valid GCP Secret Manager resource path: " + handle);
        }
    }

    private static String parentSecretName(String handle) {
        Matcher m = matchOrNull(handle);
        if (m == null) {
            throw new PermanentAgentException("SM_HANDLE_INVALID",
                    "Handle is not a valid GCP Secret Manager resource path: " + handle);
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

    private static String normalizePrefix(String prefix) {
        if (prefix == null || prefix.isBlank()) return "";
        return prefix;
    }

    private RuntimeException classifyRead(String handle, ApiException e) {
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.fromGcp(e, "SM_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("gcp sm secret read", handle, e);
        }
        return new TransientAgentException("SM_HTTP_ERROR",
                "gRPC error reading secret from " + handle + ": " + e.getMessage(), e);
    }

    private RuntimeException classifyWrite(String nameOrHandle, ApiException e) {
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.fromGcp(e, "SM_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("gcp sm secret write", nameOrHandle, e);
        }
        return new TransientAgentException("SM_WRITE_FAILED",
                "gRPC error writing secret '" + nameOrHandle + "': " + e.getMessage(), e);
    }
}
