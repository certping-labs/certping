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
import com.certping.agent.exception.RateLimitClassifier;
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
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.model.AcmException;
import software.amazon.awssdk.services.acm.model.Tag;
import software.amazon.awssdk.services.cloudfront.CloudFrontClient;
import software.amazon.awssdk.services.cloudfront.model.CloudFrontException;
import software.amazon.awssdk.services.cloudfront.model.DistributionConfig;
import software.amazon.awssdk.services.cloudfront.model.GetDistributionConfigResponse;
import software.amazon.awssdk.services.cloudfront.model.GetDistributionResponse;
import software.amazon.awssdk.services.cloudfront.model.UpdateDistributionResponse;
import software.amazon.awssdk.services.cloudfront.model.ViewerCertificate;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * AWS CloudFront deployment — one credential = one distribution.
 *
 * <p>Scope: {@link AwsCloudFrontScope} — single {@code distributionId} lives here.
 * <br>Targets: empty — nothing to select (distribution is in scope).
 * <br>Result: flat {@code {"arn": "<acm-arn>"}} — same as all AWS adapters.
 *
 * <p>The adapter imports the cert to ACM (always us-east-1), then updates the
 * distribution's viewer certificate. TLS policy and SSL support method are preserved
 * from the existing distribution config — CertPing deploys certs, it doesn't manage
 * distribution TLS settings.
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AWS_CLOUDFRONT)
@RequiredArgsConstructor
public class AwsCloudFrontDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "AWS CloudFront";
    private static final String CLOUDFRONT_REGION = "us-east-1";
    private static final int MAX_UPDATE_ATTEMPTS = 3;
    private static final int DEPLOY_POLL_ATTEMPTS = 60;
    private static final long DEPLOY_POLL_INTERVAL_MS = 30_000L;

    private final SecretStore secretStore;
    private final AwsAcmImportService acmImportService;
    private final AwsCloudCredentialResolver awsCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AwsCloudFrontScope scope = parseScope(message.getCredentialScopeJson());
        AwsAuthMode authMode = AwsScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);

        AwsAuthSecret kv = readKvSecret(message);
        AwsAuthScope authScope = AwsScopeSupport.toAuthScope(
                CLOUDFRONT_REGION, scope.roleArn(), scope.externalId());
        AwsCredentialsProvider creds = awsCredentialResolver.resolve(authMode, authScope, kv, CTX);

        String domain = requireDomain(message.getDomain(), message.getCertificateXref());
        String existingArn = parsePriorArn(message.getConfigJson());
        boolean isFirstDeploy = existingArn == null || existingArn.isBlank();
        String distributionId = scope.distributionId().trim();

        String desiredArn = acmImportService.importCertificate(
                bundle, CLOUDFRONT_REGION, creds,
                isFirstDeploy ? null : existingArn,
                isFirstDeploy ? buildTags(domain, message) : List.of());

        log.info("{} deploy: distributionId={}, arn={}, xref={}, isFirstDeploy={}",
                CTX, distributionId, desiredArn, message.getCertificateXref(), isFirstDeploy);

        try (CloudFrontClient cf = CloudFrontClient.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(creds)
                .build();
             AcmClient acm = AcmClient.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(creds)
                .build()) {

            String oldArn = null;
            if (isFirstDeploy) {
                oldArn = requireExistingAcmArn(cf, distributionId);
            }

            if (isFirstDeploy || !desiredArn.equals(getDistributionCertArn(cf, distributionId))) {
                updateDistributionWithRetry(cf, distributionId, desiredArn);
                waitForDeployed(cf, distributionId);
                ensureDistributionUsesCert(cf, distributionId, desiredArn);
            }

            if (isFirstDeploy && oldArn != null && !oldArn.equals(desiredArn)) {
                deleteOldCert(acm, oldArn);
            }

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof AwsServiceException ase) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromAws(ase, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("aws CloudFront update", distributionId, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws CloudFront update", distributionId, e);
            }
            throw new PermanentAgentException("DEPLOY_CLOUDFRONT_FAILED",
                    "CloudFront deployment failed: " + e.getMessage(), e);
        }

        return DeploymentResult.of(desiredArn, toResultJson(desiredArn));
    }

    // ---------- parsing ----------

    void validateScope(AwsCloudFrontScope scope) {
        if (scope.distributionId() == null || scope.distributionId().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.distributionId is required");
        }
    }

    private AwsCloudFrontScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AwsCloudFrontScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AwsAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AwsAuthSecret.empty();
        }
        return AwsScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    private String parsePriorArn(String configJson) {
        if (configJson == null || configJson.isBlank()) return null;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = objectMapper.readValue(configJson, Map.class);
            Object arn = map.get("arn");
            return arn == null ? null : arn.toString();
        } catch (Exception e) {
            log.warn("Failed to parse ARN from configJson='{}': {}", configJson, e.getMessage());
            return null;
        }
    }

    private String toResultJson(String arn) {
        return "{\"arn\":\"" + arn + "\"}";
    }

    // ---------- helpers ----------

    private String requireDomain(String rawDomain, String certXref) {
        String domain = CertificateIdentityUtils.normaliseDomain(rawDomain);
        if (domain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                    "CERT_DEPLOYMENT message missing required domain for xref=" + certXref);
        }
        return domain;
    }

    private String getDistributionCertArn(CloudFrontClient cf, String distributionId) {
        try {
            GetDistributionConfigResponse resp = cf.getDistributionConfig(r -> r.id(distributionId));
            ViewerCertificate vc = resp.distributionConfig().viewerCertificate();
            return vc != null ? vc.acmCertificateArn() : null;
        } catch (SdkException e) {
            return null;
        }
    }

    private String requireExistingAcmArn(CloudFrontClient cf, String distributionId) {
        GetDistributionConfigResponse resp = cf.getDistributionConfig(r -> r.id(distributionId));
        ViewerCertificate viewerCert = resp.distributionConfig().viewerCertificate();
        if (viewerCert == null) {
            throw new PermanentAgentException("DEPLOY_CLOUDFRONT_INVALID_CONFIG",
                    "CloudFront distribution missing ViewerCertificate: " + distributionId);
        }
        if (Boolean.TRUE.equals(viewerCert.cloudFrontDefaultCertificate())) {
            throw new PermanentAgentException("DEPLOY_CLOUDFRONT_DEFAULT_CERT",
                    "CloudFront distribution uses default certificate; rotation not applicable: " + distributionId);
        }
        if (viewerCert.iamCertificateId() != null && !viewerCert.iamCertificateId().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CLOUDFRONT_IAM_CERT",
                    "CloudFront distribution uses IAM certificate; ACM-based rotation required: " + distributionId);
        }
        String arn = viewerCert.acmCertificateArn();
        if (arn == null || arn.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CLOUDFRONT_INVALID_CONFIG",
                    "CloudFront distribution missing ACM certificate ARN: " + distributionId);
        }
        return arn;
    }

    private void updateDistributionWithRetry(CloudFrontClient cf, String distributionId, String newArn) {
        for (int attempt = 1; attempt <= MAX_UPDATE_ATTEMPTS; attempt++) {
            GetDistributionConfigResponse resp = cf.getDistributionConfig(r -> r.id(distributionId));
            DistributionConfig existing = resp.distributionConfig();
            DistributionConfig updated = swapCertArn(existing, newArn);

            try {
                UpdateDistributionResponse upd = cf.updateDistribution(r -> r
                        .id(distributionId)
                        .distributionConfig(updated)
                        .ifMatch(resp.eTag()));
                log.info("{} UpdateDistribution submitted: distId={}, status={}",
                        CTX, distributionId, upd.distribution().status());
                return;
            } catch (CloudFrontException e) {
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("aws CloudFront update", distributionId, e);
                }
                String code = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "";
                if ("PreconditionFailed".equals(code) && attempt < MAX_UPDATE_ATTEMPTS) {
                    log.warn("{} ETag mismatch for distribution {} (attempt {}/{}), retrying",
                            CTX, distributionId, attempt, MAX_UPDATE_ATTEMPTS);
                    continue;
                }
                throw new TransientAgentException("DEPLOY_CLOUDFRONT_ERROR",
                        "CloudFront update failed: " + e.getMessage(), e);
            } catch (SdkException e) {
                if (e instanceof AwsServiceException ase) {
                    Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                            RateLimitClassifier.fromAws(ase, "DEPLOY_PROVIDER_THROTTLED");
                    if (rlt.isPresent()) {
                        throw rlt.get().toRetryable("aws CloudFront update", distributionId, e);
                    }
                }
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("aws CloudFront update", distributionId, e);
                }
                throw new TransientAgentException("DEPLOY_CLOUDFRONT_ERROR",
                        "CloudFront update failed: " + e.getMessage(), e);
            }
        }
        throw new TransientAgentException("DEPLOY_CLOUDFRONT_ERROR",
                "CloudFront update failed after retries for distribution " + distributionId);
    }

    DistributionConfig swapCertArn(DistributionConfig existing, String newArn) {
        ViewerCertificate current = existing.viewerCertificate();
        ViewerCertificate updatedCert = ViewerCertificate.builder()
                .acmCertificateArn(newArn)
                .sslSupportMethod(current != null ? current.sslSupportMethod() : null)
                .minimumProtocolVersion(current != null ? current.minimumProtocolVersion() : null)
                .cloudFrontDefaultCertificate(false)
                .build();
        return existing.toBuilder().viewerCertificate(updatedCert).build();
    }

    private void waitForDeployed(CloudFrontClient cf, String distributionId) throws Exception {
        for (int i = 0; i < DEPLOY_POLL_ATTEMPTS; i++) {
            sleepForDeployPoll();
            GetDistributionResponse resp = cf.getDistribution(r -> r.id(distributionId));
            String status = resp.distribution().status();
            log.info("{} status: distId={}, status={}", CTX, distributionId, status);
            if ("Deployed".equals(status)) return;
        }
        throw new TransientAgentException("DEPLOY_CLOUDFRONT_TIMEOUT",
                "CloudFront distribution did not reach Deployed: " + distributionId);
    }

    private void ensureDistributionUsesCert(CloudFrontClient cf, String distributionId, String expectedArn) {
        GetDistributionConfigResponse resp = cf.getDistributionConfig(r -> r.id(distributionId));
        String currentArn = resp.distributionConfig().viewerCertificate().acmCertificateArn();
        if (!expectedArn.equals(currentArn)) {
            throw new PermanentAgentException("DEPLOY_CLOUDFRONT_VERIFY_FAILED",
                    "CloudFront distribution did not apply new certificate: " + distributionId);
        }
    }

    private void deleteOldCert(AcmClient acm, String oldArn) {
        try {
            acm.deleteCertificate(r -> r.certificateArn(oldArn));
            log.info("Deleted old ACM certificate: {}", oldArn);
        } catch (AcmException e) {
            log.warn("Failed to delete old ACM certificate {}: {}", oldArn, e.getMessage());
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

    void sleepForDeployPoll() throws InterruptedException {
        Thread.sleep(DEPLOY_POLL_INTERVAL_MS);
    }
}
