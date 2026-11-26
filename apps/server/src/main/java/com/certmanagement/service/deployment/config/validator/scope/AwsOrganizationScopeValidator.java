// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.regex.Pattern;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalString;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code AWS_ORGANIZATION} discovery scope:
 * {@code { authMode, region, roleArn?, externalId?, memberRoleName?, accountIds?[], regions?[] }}.
 */
@Component
public class AwsOrganizationScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AWS_ORGANIZATION";
    private static final Set<String> AUTH_MODES = Set.of("STATIC_KEYS", "ASSUME_ROLE", "INSTANCE_PROFILE");
    private static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");
    private static final Pattern REGION = Pattern.compile("[a-z]{2}(-[a-z]+)+-\\d");
    private static final Pattern ROLE_NAME = Pattern.compile("[\\w+=,.@/-]{1,64}");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AWS_ORGANIZATION);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        String authMode = requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        requireString(configJson, "region", CTX);
        if ("ASSUME_ROLE".equals(authMode)) {
            requireString(configJson, "roleArn", CTX);
        }
        optionalString(configJson, "externalId");
        String memberRole = optionalString(configJson, "memberRoleName");
        if (memberRole != null && !ROLE_NAME.matcher(memberRole).matches()) {
            throw new BadRequestException(CTX + ": memberRoleName is not a valid IAM role name");
        }
        checkList(configJson, "accountIds", ACCOUNT_ID, "12-digit AWS account IDs");
        checkList(configJson, "regions", REGION, "AWS region names like us-east-1");
    }

    private static void checkList(JsonNode root, String field, Pattern pattern, String hint) {
        JsonNode list = root.get(field);
        if (list == null || list.isNull()) {
            return;
        }
        if (!list.isArray()) {
            throw new BadRequestException(CTX + ": " + field + " must be a list of " + hint);
        }
        for (JsonNode item : list) {
            if (!item.isString() || !pattern.matcher(item.asString().trim()).matches()) {
                throw new BadRequestException(CTX + ": " + field + " must be a list of " + hint);
            }
        }
    }
}
