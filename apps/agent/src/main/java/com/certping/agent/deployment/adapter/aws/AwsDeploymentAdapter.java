// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.acm.model.Tag;

import java.util.List;
import java.util.Map;

/**
 * AWS ACM standalone deployment.
 *
 * <p>KV secret: {@code {accessKeyId, secretAccessKey}} (or empty for INSTANCE_PROFILE).
 * <br>Scope: {@link AwsAcmScope}.
 * <br>Targets: empty for ACM standalone (the cert <i>is</i> the deployment).
 * <br>Result (on wire as {@code configJson}): {@code {"arn":"..."}}.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AWS_ACM)
@RequiredArgsConstructor
public class AwsDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "AWS ACM";

    private final SecretStore secretStore;
    private final AwsAcmImportService acmImportService;
    private final AwsCloudCredentialResolver awsCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AwsAcmScope scope = parseScope(message.getCredentialScopeJson());
        AwsAuthMode authMode = AwsScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);

        AwsAuthSecret kv = readKvSecret(message);
        AwsAuthScope authScope = AwsScopeSupport.toAuthScope(
                scope.region(), scope.roleArn(), scope.externalId());
        AwsCredentialsProvider creds = awsCredentialResolver.resolve(authMode, authScope, kv, CTX);

        String xref = message.getCertificateXref();
        String domain = requireDomain(message.getDomain(), xref);

        // Result is sent on the wire as `configJson` (the unwrapped result slice from the server).
        String existingArn = parseArn(message.getConfigJson());
        boolean isFirstDeploy = existingArn == null || existingArn.isBlank();

        log.info("AWS ACM deploy: authMode={}, region={}, xref={}, domain={}, isFirstDeploy={}",
                authMode, scope.region(), xref, domain, isFirstDeploy);

        try {
            String arn = acmImportService.importCertificate(
                    bundle,
                    scope.region(),
                    creds,
                    existingArn,
                    isFirstDeploy ? buildTags(domain, message) : List.of());

            log.info("AWS ACM certificate imported: domain={}, arn={}", domain, arn);
            return DeploymentResult.of(arn, toArnJson(arn));

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_AWS_FAILED",
                    "Unexpected error during AWS ACM deployment: " + e.getMessage(), e);
        }
    }

    void validateScope(AwsAcmScope scope) {
        if (scope.region() == null || scope.region().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.region is required");
        }
    }

    private AwsAcmScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AwsAcmScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AwsAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AwsAuthSecret.empty();
        }
        String credRaw = secretStore.read(message.getDeploymentCredHandle());
        return AwsScopeSupport.parseKvSecret(objectMapper, credRaw, CTX);
    }

    private String requireDomain(String rawDomain, String certXref) {
        String domain = CertificateIdentityUtils.normaliseDomain(rawDomain);
        if (domain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                    "CERT_DEPLOYMENT message missing required domain for xref=" + certXref);
        }
        return domain;
    }

    private String parseArn(String configJson) {
        if (configJson == null || configJson.isBlank()) return null;
        try {
            @SuppressWarnings("unchecked")
            Map<String, String> map = objectMapper.readValue(configJson, Map.class);
            return map.get("arn");
        } catch (Exception e) {
            log.warn("Failed to parse ARN from configJson='{}': {}", configJson, e.getMessage());
            return null;
        }
    }

    private String toArnJson(String arn) {
        try {
            return objectMapper.writeValueAsString(Map.of("arn", arn));
        } catch (Exception e) {
            return "{\"arn\":\"" + arn + "\"}";
        }
    }

    private List<Tag> buildTags(String domain, CertDeploymentMessage message) {
        String orgId = message.getOrganizationId() == null ? "" : message.getOrganizationId();
        if (!domain.isBlank()) {
            return List.of(
                    Tag.builder().key("ManagedBy").value("certping-agent").build(),
                    Tag.builder().key("OrganizationId").value(orgId).build(),
                    Tag.builder().key("Domain").value(domain).build());
        }
        return List.of(
                Tag.builder().key("ManagedBy").value("certping-agent").build(),
                Tag.builder().key("OrganizationId").value(orgId).build());
    }
}
