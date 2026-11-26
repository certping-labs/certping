// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalInt;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalString;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code AKAMAI_CPS} credential scope:
 * {@code { host, enrollmentId, pollIntervalSeconds?, pollTimeoutMinutes?, waitForStatus? }}.
 *
 * <p>Auth is always EdgeGrid (the KV secret carries the three-token tuple). Polling tunables
 * have sensible defaults in the adapter.
 */
@Component
public class AkamaiScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AKAMAI_CPS";

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AKAMAI_CPS);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        requireString(configJson, "host", CTX);
        requireString(configJson, "enrollmentId", CTX);
        optionalInt(configJson, "pollIntervalSeconds", CTX);
        optionalInt(configJson, "pollTimeoutMinutes", CTX);
        optionalString(configJson, "waitForStatus");
    }
}
