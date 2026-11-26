// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code CLOUDFLARE_EDGE} credential scope:
 * {@code { zoneId, bundleMethod?, certType? }}.
 *
 * <p>Auth is always API_TOKEN (the KV secret carries the token). {@code bundleMethod}
 * defaults to {@code ubiquitous} and {@code certType} to {@code sni_custom} in the adapter.
 */
@Component
public class CloudflareScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "CLOUDFLARE_EDGE";
    private static final Set<String> BUNDLE_METHODS = Set.of("ubiquitous", "optimal", "force");
    private static final Set<String> CERT_TYPES = Set.of("sni_custom", "legacy_custom");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.CLOUDFLARE_EDGE);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        requireString(configJson, "zoneId", CTX);
        optionalOneOf(configJson, "bundleMethod", BUNDLE_METHODS, CTX);
        optionalOneOf(configJson, "certType", CERT_TYPES, CTX);
    }
}
