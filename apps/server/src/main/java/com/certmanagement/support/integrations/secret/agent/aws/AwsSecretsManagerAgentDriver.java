// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.aws;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties.AwsAuthMode;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties.AwsSecretsManager;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceExistsException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsWebIdentityTokenFileCredentialsProvider;

import java.net.URI;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AWS Secrets Manager-backed {@link AgentSecretStore}. Handles are ARNs
 * ({@code arn:aws:secretsmanager:<region>:<accountId>:secret:<name>[-<6charSuffix>]}).
 *
 * <p>Only activated when {@code certping.agent-secret-store.provider=AWS_SECRETS_MANAGER}. Mirrors
 * the cert-lifecycle-side driver's ownership + handle semantics so a handle produced here parses
 * cleanly on the agent side.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "certping.agent-secret-store.provider", havingValue = "AWS_SECRETS_MANAGER")
public class AwsSecretsManagerAgentDriver implements AgentSecretStore {

    private static final Pattern HANDLE_PATTERN = Pattern.compile(
            "^arn:aws:secretsmanager:([a-z0-9-]+):(\\d{12}):secret:([A-Za-z0-9/_+=.@-]+?)(?:-([A-Za-z0-9]{6}))?$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9/_-]{1,127}$");
    /** GetSecretValue's InvalidRequestException text for a secret scheduled for deletion. */
    private static final String MARKED_FOR_DELETION = "marked for deletion";

    private final AwsSecretsManager properties;

    private AwsCredentialsProvider credentialsProvider;
    private SecretsManagerClient client;
    private String ownRegion;
    private String ownAccountId;
    private String ownNamePrefix;

    public AwsSecretsManagerAgentDriver(AgentSecretStoreProperties properties) {
        this.properties = properties.getAwsSecretsManager();
    }

    @PostConstruct
    void init() {
        if (properties.getRegion() == null || properties.getRegion().isBlank()) {
            throw new IllegalStateException(
                    "certping.agent-secret-store.aws-secrets-manager.region is required "
                            + "when provider=AWS_SECRETS_MANAGER");
        }
        this.ownRegion = properties.getRegion();
        this.ownNamePrefix = normalizePrefix(properties.getOwnStoreNamePrefix());
        this.credentialsProvider = buildCredentialsProvider(properties.getAuthMode());
        this.client = buildClient();
        this.ownAccountId = resolveOwnAccountId();
        log.info("AwsSecretsManagerAgentDriver ready: region={}, accountId={}, authMode={}, prefix={}",
                ownRegion, ownAccountId, properties.getAuthMode(), ownNamePrefix);
    }

    @PreDestroy
    void shutdown() {
        if (client != null) {
            try { client.close(); } catch (Exception ignored) { }
        }
    }

    @Override
    public AgentSecretStoreProvider provider() {
        return AgentSecretStoreProvider.AWS_SECRETS_MANAGER;
    }

    @Override
    public String create(String name, String value) {
        requireValidName(name);
        String fullName = ownNamePrefix + name;
        try {
            CreateSecretResponse resp = client.createSecret(
                    CreateSecretRequest.builder().name(fullName).secretString(value).build());
            return resp.arn();
        } catch (ResourceExistsException existing) {
            // Idempotent upsert — same semantics as Azure setSecret.
            try {
                PutSecretValueResponse resp = client.putSecretValue(
                        PutSecretValueRequest.builder().secretId(fullName).secretString(value).build());
                return resp.arn();
            } catch (AwsServiceException e) {
                throw new IllegalStateException("Failed to overwrite AWS secret '" + name + "': " + e.getMessage(), e);
            }
        } catch (AwsServiceException e) {
            throw new IllegalStateException("Failed to create AWS secret '" + name + "': " + e.getMessage(), e);
        }
    }

    @Override
    public String read(String handle) {
        requireValidHandle(handle);
        try {
            GetSecretValueResponse resp = client.getSecretValue(
                    GetSecretValueRequest.builder().secretId(handle).build());
            return resp.secretString();
        } catch (software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException e) {
            throw new ResourceNotFoundException("Agent secret not found at handle: " + handle);
        } catch (InvalidRequestException e) {
            // AWS has no dedicated error code for a pending deletion; the message is the only signal,
            // the same way deleteIfOwned recognises one.
            if (e.getMessage() != null && e.getMessage().contains(MARKED_FOR_DELETION)) {
                throw new AgentSecretGoneException("AWS secret is marked for deletion: " + handle, e);
            }
            throw new IllegalStateException("Failed to read AWS secret at " + handle + ": " + e.getMessage(), e);
        } catch (AwsServiceException e) {
            throw new IllegalStateException("Failed to read AWS secret at " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String update(String handle, String value) {
        requireValidHandle(handle);
        if (!isOwnedByThisCertManager(handle)) {
            throw new BadRequestException(
                    "Refusing to update secret at foreign AWS handle: " + handle);
        }
        try {
            PutSecretValueResponse resp = client.putSecretValue(
                    PutSecretValueRequest.builder().secretId(handle).secretString(value).build());
            return resp.arn() != null ? resp.arn() : handle;
        } catch (software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException e) {
            throw new ResourceNotFoundException("Agent secret not found at handle: " + handle);
        } catch (AwsServiceException e) {
            throw new IllegalStateException("Failed to update AWS secret at " + handle + ": " + e.getMessage(), e);
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
        try {
            client.deleteSecret(DeleteSecretRequest.builder()
                    .secretId(handle)
                    .forceDeleteWithoutRecovery(true)
                    .build());
            log.info("Deleted agent AWS secret: handle={}", handle);
        } catch (software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException e) {
            log.debug("AWS secret already gone: handle={}", handle);
        } catch (InvalidRequestException e) {
            if (e.getMessage() != null && e.getMessage().contains("scheduled for deletion")) {
                log.debug("AWS secret already scheduled for deletion: handle={}", handle);
                return;
            }
            log.warn("AWS delete rejected for handle={}: {}", handle, e.getMessage());
        } catch (AwsServiceException e) {
            log.warn("AWS delete failed for handle={}: {}", handle, e.getMessage());
        }
    }

    @Override
    public boolean isOwnedByThisCertManager(String handle) {
        Matcher m = matchOrNull(handle);
        if (m == null) {
            return false;
        }
        return m.group(1).equals(ownRegion)
                && m.group(2).equals(ownAccountId)
                && m.group(3).startsWith(ownNamePrefix);
    }

    @Override
    public boolean isAgentCertificateHandle(String handle, String certificateXref) {
        Matcher m = matchOrNull(handle);
        if (m == null || certificateXref == null
                || !m.group(1).equals(ownRegion) || !m.group(2).equals(ownAccountId)) {
            return false;
        }
        String expectedName = ownNamePrefix + certificateXref;
        // The pattern's random-suffix group is optional, so a name that itself ends in "-xxxxxx"
        // can land in either group; accept both splits, never a partial match.
        String suffix = m.group(4);
        return m.group(3).equals(expectedName)
                || (suffix != null && (m.group(3) + "-" + suffix).equals(expectedName));
    }

    @Override
    public String handleFor(String name) {
        requireValidName(name);
        return "arn:aws:secretsmanager:" + ownRegion + ":" + ownAccountId
                + ":secret:" + ownNamePrefix + name;
    }

    private AwsCredentialsProvider buildCredentialsProvider(AwsAuthMode mode) {
        return switch (mode) {
            case WEB_IDENTITY_TOKEN -> {
                requireAuthField("role-arn", properties.getRoleArn());
                requireAuthField("web-identity-token-file", properties.getWebIdentityTokenFile());
                yield StsWebIdentityTokenFileCredentialsProvider.builder()
                        .stsClient(StsClient.builder().region(Region.of(ownRegion)).build())
                        .roleArn(properties.getRoleArn())
                        .roleSessionName("certping-cert-manager")
                        .webIdentityTokenFile(Path.of(properties.getWebIdentityTokenFile()))
                        .build();
            }
            case INSTANCE_PROFILE -> InstanceProfileCredentialsProvider.create();
            case PROFILE -> ProfileCredentialsProvider.create();
            case DEFAULT -> {
                log.info("AwsSecretsManagerAgentDriver: using DefaultCredentialsProvider chain");
                yield DefaultCredentialsProvider.create();
            }
        };
    }

    private SecretsManagerClient buildClient() {
        var b = SecretsManagerClient.builder()
                .region(Region.of(ownRegion))
                .credentialsProvider(credentialsProvider);
        if (properties.getEndpointOverride() != null && !properties.getEndpointOverride().isBlank()) {
            b.endpointOverride(URI.create(properties.getEndpointOverride()));
        }
        return b.build();
    }

    private String resolveOwnAccountId() {
        try (StsClient sts = StsClient.builder()
                .region(Region.of(ownRegion))
                .credentialsProvider(credentialsProvider)
                .build()) {
            return sts.getCallerIdentity().account();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to resolve caller identity via STS — cannot bootstrap AWS Secrets Manager driver: "
                            + e.getMessage(), e);
        }
    }

    private static void requireAuthField(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "certping.agent-secret-store.aws-secrets-manager." + name
                            + " is required for the configured auth-mode");
        }
    }

    private static void requireValidName(String name) {
        if (name == null || !NAME_PATTERN.matcher(name).matches()) {
            throw new BadRequestException(
                    "Invalid AWS secret name (must match " + NAME_PATTERN.pattern() + "): " + name);
        }
    }

    private static void requireValidHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            throw new BadRequestException("AWS secret handle is null or blank");
        }
        if (!HANDLE_PATTERN.matcher(handle).matches()) {
            throw new BadRequestException("Handle is not a valid AWS Secrets Manager ARN: " + handle);
        }
    }

    private static Matcher matchOrNull(String handle) {
        if (handle == null) return null;
        Matcher m = HANDLE_PATTERN.matcher(handle);
        return m.matches() ? m : null;
    }

    private static String normalizePrefix(String prefix) {
        return prefix == null || prefix.isBlank() ? "" : prefix;
    }
}
