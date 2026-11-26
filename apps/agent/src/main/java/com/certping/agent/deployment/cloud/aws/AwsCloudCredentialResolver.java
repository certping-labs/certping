// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.aws;

import com.certping.agent.deployment.adapter.aws.AwsAssumeRoleService;
import com.certping.agent.deployment.adapter.aws.AwsDeploymentAuthHelper;
import com.certping.agent.exception.PermanentAgentException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

/**
 * Single entry point for AWS credential resolution across all AWS-flavored adapters
 * (ACM, ALB/NLB, API GW, CloudFront, plus the AWS branch of the K8s adapter).
 *
 * <p>Reuses {@link AwsAssumeRoleService} (the same component K8s already uses) so the
 * STS path is shared. Only the auth-mode dispatch is new.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AwsCloudCredentialResolver {

    private final AwsAssumeRoleService assumeRoleService;

    /**
     * @param mode  the declared auth mode from {@code credentialScopeJson.authMode}
     * @param scope the parsed scope record (region, roleArn, etc.)
     * @param kv    parsed KV secret (may be empty for INSTANCE_PROFILE)
     * @param context  human-readable adapter name for error messages (e.g. {@code "AWS_ALB"})
     * @return an SDK-ready {@link AwsCredentialsProvider}
     */
    public AwsCredentialsProvider resolve(AwsAuthMode mode, AwsAuthScope scope, AwsAuthSecret kv, String context) {
        if (mode == null) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential is missing 'authMode'");
        }
        AwsAuthSecret secret = kv != null ? kv : AwsAuthSecret.empty();

        return switch (mode) {
            case STATIC_KEYS -> resolveStaticKeys(secret, context);
            case ASSUME_ROLE -> resolveAssumeRole(scope, secret, context);
            case INSTANCE_PROFILE -> resolveInstanceProfile(context);
        };
    }

    private AwsCredentialsProvider resolveStaticKeys(AwsAuthSecret kv, String context) {
        if (!kv.hasKeys()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " STATIC_KEYS auth mode requires accessKeyId + secretAccessKey in KV secret");
        }
        log.debug("{}: using STATIC_KEYS credentials", context);
        return StaticCredentialsProvider.create(
                AwsBasicCredentials.create(kv.accessKeyId().trim(), kv.secretAccessKey().trim()));
    }

    private AwsCredentialsProvider resolveAssumeRole(AwsAuthScope scope, AwsAuthSecret kv, String context) {
        if (scope == null || scope.roleArn() == null || scope.roleArn().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " ASSUME_ROLE auth mode requires 'roleArn' in credential scope");
        }
        if (scope.region() == null || scope.region().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " ASSUME_ROLE auth mode requires 'region' in credential scope");
        }
        AwsDeploymentAuthHelper.validateRoleArn(scope.roleArn(), context);
        AwsDeploymentAuthHelper.validateRegion(scope.region(), context);

        log.debug("{}: assuming role {} in {} (bootstrap keys present={})",
                context, scope.roleArn(), scope.region(), kv.hasKeys());
        AwsSessionCredentials sessionCreds = assumeRoleService.assumeRoleValidated(
                scope.roleArn(), scope.region(), kv.accessKeyId(), kv.secretAccessKey());
        return StaticCredentialsProvider.create(sessionCreds);
    }

    private AwsCredentialsProvider resolveInstanceProfile(String context) {
        log.debug("{}: using INSTANCE_PROFILE / default credential provider chain", context);
        return DefaultCredentialsProvider.create();
    }
}
