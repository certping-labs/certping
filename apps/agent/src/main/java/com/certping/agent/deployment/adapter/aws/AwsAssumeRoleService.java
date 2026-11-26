// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.TransientAgentException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.StsException;

import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class AwsAssumeRoleService {

    private final AgentProperties properties;

    public AwsSessionCredentials assumeRole(String roleArn, String region, String accessKeyId, String secretAccessKey) {
        String validatedRoleArn = AwsDeploymentAuthHelper.requireRoleArn(roleArn, "AWS");
        String validatedRegion = AwsDeploymentAuthHelper.requireRegion(region, "AWS");

        return assumeRoleValidated(validatedRoleArn, validatedRegion, accessKeyId, secretAccessKey);
    }

    public AwsSessionCredentials assumeRoleValidated(String roleArn,
                                                     String region,
                                                     String accessKeyId,
                                                     String secretAccessKey) {

        AgentProperties.AwsProperties awsCfg = properties.getDeployment().getAws();
        AwsCredentialsProvider credsProvider = baseCredentialsProvider(accessKeyId, secretAccessKey);

        try (StsClient stsClient = StsClient.builder()
            .region(Region.of(region))
                .credentialsProvider(credsProvider)
                .build()) {

                AssumeRoleResponse resp = stsClient.assumeRole(AssumeRoleRequest.builder()
                    .roleArn(roleArn)
                    .roleSessionName(awsCfg.getSessionName())
                    .durationSeconds(awsCfg.getSessionDurationSeconds())
                    .build());

            Credentials tempCreds = resp.credentials();
            log.debug("STS AssumeRole succeeded: expiry={}", tempCreds.expiration());
            return AwsSessionCredentials.create(
                    tempCreds.accessKeyId(),
                    tempCreds.secretAccessKey(),
                    tempCreds.sessionToken());

        } catch (StsException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws STS AssumeRole", roleArn, e);
            }
            String code = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "unknown";
            if ("AccessDenied".equals(code) || "AuthorizationError".equals(code)) {
                throw new PermanentAgentException("DEPLOY_STS_DENIED",
                        "STS AssumeRole denied for role " + roleArn + ": " + e.getMessage(), e);
            }
            if ("ValidationError".equals(code)) {
                throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                        "STS AssumeRole rejected the request for role " + roleArn + ": " + e.getMessage(), e);
            }
            throw new TransientAgentException("DEPLOY_STS_ERROR",
                    "STS AssumeRole transient error: " + e.getMessage(), e);
        }
    }

    private AwsCredentialsProvider baseCredentialsProvider(String accessKeyId, String secretAccessKey) {
        if (accessKeyId != null && !accessKeyId.isBlank() && secretAccessKey != null && !secretAccessKey.isBlank()) {
            log.debug("Using static access key credentials for STS AssumeRole");
            return StaticCredentialsProvider.create(AwsBasicCredentials.create(
                    accessKeyId.trim(), secretAccessKey.trim()));
        }
        log.debug("Using default AWS credential provider chain for STS AssumeRole");
        return DefaultCredentialsProvider.create();
    }

    public void validateAwsRoleArn(String arn) {
        AwsDeploymentAuthHelper.requireRoleArn(arn, "AWS");
    }

    public void validateAwsRegion(String region) {
        AwsDeploymentAuthHelper.requireRegion(region, "AWS");
    }
}
