// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalBoolean;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalInt;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalString;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code F5_BIGIP} credential scope:
 * {@code { bigipHost, bigipPort?, verifySsl?, partition, clientSslProfiles?,
 *         installOnly?, deviceGroup? }}.
 *
 * <p>Auth is always BASIC_AUTH (the KV secret carries username + password). All tunable
 * fields default sensibly in the adapter ({@code bigipPort=443}, {@code verifySsl=true},
 * {@code installOnly=false}).
 *
 * <p>Per-cert {@code certBaseName} lives in {@code targets} so one BIG-IP partition can host
 * many independent certs.
 */
@Component
public class F5ScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "F5_BIGIP";

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.F5_BIGIP);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        requireString(configJson, "bigipHost", CTX);

        Integer port = optionalInt(configJson, "bigipPort", CTX);
        if (port != null && (port <= 0 || port > 65535)) {
            throw new BadRequestException(CTX + " configJson.bigipPort out of range: " + port);
        }
        optionalBoolean(configJson, "verifySsl", CTX);

        requireString(configJson, "partition", CTX);

        // clientSslProfiles is optional but if present, must be a non-empty array of non-blank strings
        JsonNode profiles = configJson.get("clientSslProfiles");
        if (profiles != null && !profiles.isNull()) {
            if (!profiles.isArray() || profiles.isEmpty()) {
                throw new BadRequestException(
                        CTX + " configJson.clientSslProfiles must be a non-empty array when present");
            }
            int i = 0;
            for (JsonNode element : profiles) {
                if (!element.isString() || element.asString().isBlank()) {
                    throw new BadRequestException(
                            CTX + " configJson.clientSslProfiles[" + i + "] must be a non-blank string");
                }
                i++;
            }
        }

        optionalBoolean(configJson, "installOnly", CTX);
        optionalString(configJson, "deviceGroup");
    }
}
