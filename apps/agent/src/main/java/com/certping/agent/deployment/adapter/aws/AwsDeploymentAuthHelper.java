// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

public final class AwsDeploymentAuthHelper {

    public record AwsAuthContext(String roleArn, String region, AwsSessionCredentials sessionCredentials) {}

    private AwsDeploymentAuthHelper() {}

    public static <T> T parseCredential(ObjectMapper objectMapper, String raw, Class<T> type, String context) {
        try {
            return objectMapper.readValue(raw, type);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + context + " credential JSON: " + e.getMessage(), e);
        }
    }

    public static String requireField(String value, String field, String context) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential missing required field: " + field);
        }
        return value;
    }

    public static String requireRoleArn(String roleArn, String context) {
        String value = requireField(roleArn, "roleArn", context);
        validateRoleArn(value, context);
        return value;
    }

    public static String requireRegion(String region, String context) {
        String value = requireField(region, "region", context);
        validateRegion(value, context);
        return value;
    }

    public static void validateRoleArn(String arn, String context) {
        if (!arn.matches("arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9/_+=,.@-]+")) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential 'roleArn' format is invalid: '" + arn +
                    "'. Expected: arn:aws:iam::<12-digit-account>:role/<role-name>");
        }
    }

    public static void validateRegion(String region, String context) {
        if (!region.matches("^[a-z]{2,4}-[a-z]+-\\d+$")) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential 'region' format is invalid: '" + region +
                    "'. Expected format: <geo>-<direction>-<digit> (e.g. us-east-1)");
        }
    }

    public static AwsSessionCredentials assumeRole(AwsAssumeRoleService assumeRoleService,
                                                   String roleArn,
                                                   String region,
                                                   String accessKeyId,
                                                   String secretAccessKey) {
        return assumeRoleService.assumeRole(roleArn, region, accessKeyId, secretAccessKey);
    }

    public static AwsAuthContext buildAuthContext(AwsAssumeRoleService assumeRoleService,
                                                  String roleArn,
                                                  String region,
                                                  String accessKeyId,
                                                  String secretAccessKey,
                                                  String context) {
        String validatedRoleArn = requireRoleArn(roleArn, context);
        String validatedRegion = requireRegion(region, context);
        AwsSessionCredentials sessionCreds = assumeRoleService.assumeRoleValidated(
                validatedRoleArn, validatedRegion, accessKeyId, secretAccessKey);
        return new AwsAuthContext(validatedRoleArn, validatedRegion, sessionCreds);
    }
}
