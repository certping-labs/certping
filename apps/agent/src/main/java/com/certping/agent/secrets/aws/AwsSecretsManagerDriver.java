// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.aws;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreDriver;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProperties.AwsAuthMode;
import com.certping.agent.secrets.SecretStoreProperties.AwsSecretsManagerProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;
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
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsWebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import java.net.URI;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
@ConditionalOnProperty(name = "agent.secret-store.provider", havingValue = "AWS_SECRETS_MANAGER")
public class AwsSecretsManagerDriver implements SecretStoreDriver {

    // AWS's SDK accepts either a full ARN (with the 6-char suffix AWS appends on create)
    // or a partial ARN (no suffix) or the friendly name alone. The suffix group is optional
    // so handleFor("<name>") — used by the startup probe — produces a value read() will accept
    // and forward to AWS, which then answers NOT_FOUND (the probe's expected outcome).
    private static final Pattern HANDLE_PATTERN = Pattern.compile(
            "^arn:aws:secretsmanager:([a-z0-9-]+):(\\d{12}):secret:([A-Za-z0-9/_+=.@-]+?)(?:-([A-Za-z0-9]{6}))?$");

    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,127}$");

    private final AwsSecretsManagerProperties properties;
    private final String activeProfile;

    private AwsCredentialsProvider credentialsProvider;
    private SecretsManagerClient ownRegionClient;
    private String ownRegion;
    private String ownAccountId;
    private String ownNamePrefix;

    private final ConcurrentHashMap<String, SecretsManagerClient> perRegionClients = new ConcurrentHashMap<>();

    @Autowired
    public AwsSecretsManagerDriver(SecretStoreProperties properties,
                                   @Value("${spring.profiles.active:${SPRING_PROFILES_ACTIVE:}}") String activeProfile) {
        this.properties = properties.getAwsSecretsManager();
        this.activeProfile = activeProfile == null ? "" : activeProfile;
    }

    // Test seam: inject a pre-built client + account id, skip STS lookup.
    AwsSecretsManagerDriver(SecretStoreProperties properties, String activeProfile,
                            SecretsManagerClient injectedClient, String injectedAccountId) {
        this.properties = properties.getAwsSecretsManager();
        this.activeProfile = activeProfile == null ? "" : activeProfile;
        this.ownRegionClient = injectedClient;
        this.ownAccountId = injectedAccountId;
        this.ownRegion = this.properties.getRegion();
        this.ownNamePrefix = normalizePrefix(this.properties.getOwnStoreNamePrefix());
        this.perRegionClients.put(this.ownRegion, injectedClient);
    }

    @PostConstruct
    void init() {
        if (ownRegionClient != null) {
            return;
        }
        if (properties.getRegion() == null || properties.getRegion().isBlank()) {
            throw new IllegalStateException(
                    "agent.secret-store.aws-secrets-manager.region is required when provider=AWS_SECRETS_MANAGER");
        }
        this.ownRegion = properties.getRegion();
        this.ownNamePrefix = normalizePrefix(properties.getOwnStoreNamePrefix());
        this.credentialsProvider = buildCredentialsProvider(properties.getAuthMode());
        this.ownRegionClient = buildClient(ownRegion);
        this.perRegionClients.put(ownRegion, ownRegionClient);
        this.ownAccountId = resolveOwnAccountId();
        log.info("AwsSecretsManagerDriver ready: region={}, accountId={}, authMode={}, prefix={}",
                ownRegion, ownAccountId, properties.getAuthMode(), ownNamePrefix);
    }

    @PreDestroy
    void shutdown() {
        for (SecretsManagerClient c : perRegionClients.values()) {
            try { c.close(); } catch (Exception ignored) { }
        }
    }

    @Override
    public SecretStoreProvider provider() {
        return SecretStoreProvider.AWS_SECRETS_MANAGER;
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
        String region = m.group(1);
        String accountId = m.group(2);
        String name = m.group(3);
        return region.equals(ownRegion)
                && accountId.equals(ownAccountId)
                && name.startsWith(ownNamePrefix);
    }

    @Override
    public String handleFor(String name) {
        assertValidName(name);
        return "arn:aws:secretsmanager:" + ownRegion + ":" + ownAccountId
                + ":secret:" + ownNamePrefix + name;
    }

    @Override
    public String read(String handle) {
        requireHandle(handle);
        SecretsManagerClient client = clientForHandle(handle);
        try {
            GetSecretValueResponse resp = client.getSecretValue(
                    GetSecretValueRequest.builder().secretId(handle).build());
            return resp.secretString();
        } catch (ResourceNotFoundException e) {
            throw new PermanentAgentException("SM_SECRET_NOT_FOUND",
                    "Secret not found at handle: " + handle, e);
        } catch (AwsServiceException e) {
            throw classifyRead(handle, e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_READ_FAILED",
                    "Failed to read secret from " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String create(String name, String value) {
        assertValidName(name);
        String fullName = ownNamePrefix + name;
        try {
            CreateSecretResponse resp = ownRegionClient.createSecret(
                    CreateSecretRequest.builder().name(fullName).secretString(value).build());
            return resp.arn();
        } catch (ResourceExistsException existing) {
            // Idempotent upsert — same semantics as Azure setSecret.
            try {
                PutSecretValueResponse resp = ownRegionClient.putSecretValue(
                        PutSecretValueRequest.builder().secretId(fullName).secretString(value).build());
                return resp.arn();
            } catch (AwsServiceException e) {
                throw classifyWrite(name, e);
            }
        } catch (AwsServiceException e) {
            throw classifyWrite(name, e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_WRITE_FAILED",
                    "Failed to create secret '" + name + "': " + e.getMessage(), e);
        }
    }

    @Override
    public String update(String handle, String value) {
        requireHandle(handle);
        SecretsManagerClient client = clientForHandle(handle);
        try {
            PutSecretValueResponse resp = client.putSecretValue(
                    PutSecretValueRequest.builder().secretId(handle).secretString(value).build());
            return resp.arn() != null ? resp.arn() : handle;
        } catch (ResourceNotFoundException e) {
            throw new PermanentAgentException("SM_SECRET_NOT_FOUND",
                    "Secret not found at handle: " + handle, e);
        } catch (AwsServiceException e) {
            throw classifyWriteAtHandle(handle, e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_WRITE_FAILED",
                    "Failed to write secret to " + handle + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void delete(String handle) {
        requireHandle(handle);
        SecretsManagerClient client = clientForHandle(handle);
        try {
            // Own-store handles: force-delete purges the tombstone so the same
            // name can be reused immediately — matches Azure driver's purge.
            // Foreign handles: honour the configured recovery window; customer
            // decides recovery policy on their own secrets.
            DeleteSecretRequest.Builder req = DeleteSecretRequest.builder().secretId(handle);
            if (isOwnedByThisAgent(handle)) {
                req.forceDeleteWithoutRecovery(true);
            } else {
                req.recoveryWindowInDays((long) properties.getRecoveryWindowDays());
            }
            client.deleteSecret(req.build());
        } catch (ResourceNotFoundException e) {
            log.info("Secret already absent at {} — treating as success", handle);
        } catch (InvalidRequestException e) {
            // "Already scheduled for deletion" — idempotent, treat as success.
            if (e.getMessage() != null && e.getMessage().contains("scheduled for deletion")) {
                log.info("Secret at {} already scheduled for deletion — treating as success", handle);
                return;
            }
            throw new PermanentAgentException("SM_INVALID_REQUEST",
                    "Delete rejected at " + handle + ": " + e.getMessage(), e);
        } catch (AwsServiceException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAws(e, "SM_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws sm secret delete", handle, e);
            }
            throw new TransientAgentException("SM_DELETE_FAILED",
                    "Failed to delete secret at " + handle + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new TransientAgentException("SM_DELETE_FAILED",
                    "Failed to delete secret at " + handle + ": " + e.getMessage(), e);
        }
    }

    private AwsCredentialsProvider buildCredentialsProvider(AwsAuthMode mode) {
        switch (mode) {
            case WEB_IDENTITY_TOKEN -> {
                requireAuthField("role-arn", properties.getRoleArn());
                requireAuthField("web-identity-token-file", properties.getWebIdentityTokenFile());
                return StsWebIdentityTokenFileCredentialsProvider.builder()
                        .stsClient(withEndpoint(StsClient.builder().region(Region.of(ownRegion))).build())
                        .roleArn(properties.getRoleArn())
                        .roleSessionName("certping-agent")
                        .webIdentityTokenFile(Path.of(properties.getWebIdentityTokenFile()))
                        .build();
            }
            case INSTANCE_PROFILE -> {
                return InstanceProfileCredentialsProvider.create();
            }
            case PROFILE -> {
                return ProfileCredentialsProvider.create();
            }
            case STATIC -> {
                String key = System.getenv("AWS_ACCESS_KEY_ID");
                String secret = System.getenv("AWS_SECRET_ACCESS_KEY");
                if (key == null || key.isBlank() || secret == null || secret.isBlank()) {
                    throw new IllegalStateException(
                            "auth-mode=STATIC requires AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars");
                }
                return StaticCredentialsProvider.create(AwsBasicCredentials.create(key, secret));
            }
            case DEFAULT -> {
                log.warn("Using DefaultCredentialsProvider chain — prefer explicit auth-mode in production");
                return DefaultCredentialsProvider.create();
            }
        }
        throw new IllegalStateException("Unhandled AwsAuthMode: " + mode);
    }

    private SecretsManagerClient buildClient(String region) {
        return withEndpoint(SecretsManagerClient.builder()
                .region(Region.of(region))
                .credentialsProvider(credentialsProvider)).build();
    }

    StsClient buildStsClient() {
        return withEndpoint(StsClient.builder()
                .region(Region.of(ownRegion))
                .credentialsProvider(credentialsProvider)).build();
    }

    private <B extends AwsClientBuilder<B, ?>> B withEndpoint(B builder) {
        String override = properties.getEndpointOverride();
        return override == null || override.isBlank() ? builder : builder.endpointOverride(URI.create(override));
    }

    private SecretsManagerClient clientForHandle(String handle) {
        Matcher m = matchOrNull(handle);
        if (m == null) {
            throw new PermanentAgentException("SM_HANDLE_INVALID",
                    "Handle is not a valid Secrets Manager ARN: " + handle);
        }
        String region = m.group(1);
        if (region.equals(ownRegion)) {
            return ownRegionClient;
        }
        return perRegionClients.computeIfAbsent(region, this::buildClient);
    }

    private String resolveOwnAccountId() {
        try (StsClient sts = buildStsClient()) {
            GetCallerIdentityResponse who = sts.getCallerIdentity();
            return who.account();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to resolve caller identity via STS — cannot bootstrap AWS Secrets Manager driver: "
                            + e.getMessage(), e);
        }
    }

    private static void requireAuthField(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "agent.secret-store.aws-secrets-manager." + name + " is required for the configured auth-mode");
        }
    }

    private void requireHandle(String handle) {
        if (handle == null || handle.isBlank()) {
            throw new PermanentAgentException("SM_HANDLE_BLANK", "Secret handle is null or blank");
        }
        if (!parsesHandle(handle)) {
            throw new PermanentAgentException("SM_HANDLE_INVALID",
                    "Handle is not a valid Secrets Manager ARN: " + handle);
        }
    }

    private static Matcher matchOrNull(String handle) {
        if (handle == null) return null;
        Matcher m = HANDLE_PATTERN.matcher(handle);
        return m.matches() ? m : null;
    }

    private static String normalizePrefix(String prefix) {
        if (prefix == null || prefix.isBlank()) return "";
        return prefix;
    }

    private RuntimeException classifyRead(String handle, AwsServiceException e) {
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.fromAws(e, "SM_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("aws sm secret read", handle, e);
        }
        if (e.statusCode() == 403) {
            return new PermanentAgentException("SM_ACCESS_DENIED",
                    "Access denied reading secret: " + handle, e);
        }
        return new TransientAgentException("SM_HTTP_ERROR",
                "HTTP error reading secret: " + e.getMessage(), e);
    }

    private RuntimeException classifyWrite(String name, AwsServiceException e) {
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.fromAws(e, "SM_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("aws sm secret write", name, e);
        }
        return new TransientAgentException("SM_WRITE_FAILED",
                "Failed to write secret '" + name + "': " + e.getMessage(), e);
    }

    private RuntimeException classifyWriteAtHandle(String handle, AwsServiceException e) {
        Optional<RateLimitClassifier.RateLimitVerdict> rl =
                RateLimitClassifier.fromAws(e, "SM_PROVIDER_THROTTLED");
        if (rl.isPresent()) {
            return rl.get().toRetryable("aws sm secret write", handle, e);
        }
        if (e.statusCode() == 403) {
            return new PermanentAgentException("SM_ACCESS_DENIED",
                    "Access denied writing secret: " + handle, e);
        }
        return new TransientAgentException("SM_HTTP_ERROR",
                "HTTP error writing secret: " + e.getMessage(), e);
    }
}
