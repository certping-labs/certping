// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Validates AWS API Gateway (REST + HTTP) deployment targets.
 *
 * <p>New flat shape: {@code { "domainNames": [ "api.example.com" ] }}.
 * Custom domains live in the credential scope ({@code configJson.customDomains}).
 * Targets select a subset of those domains for this certificate.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AwsApiGatewayTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(
            TargetType.AWS_API_GW_REST, TargetType.AWS_API_GW_HTTP);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        if (requestedTargets == null || !requestedTargets.isObject()) {
            throw new BadRequestException("API Gateway targets must be a JSON object");
        }
        JsonNode list = requestedTargets.get("domainNames");
        if (list == null || !list.isArray() || list.isEmpty()) {
            throw new BadRequestException("API Gateway targets.domainNames must be a non-empty array");
        }

        Set<String> scopeDomains = parseScopeCustomDomains(credential);
        Set<String> seen = new LinkedHashSet<>();
        ArrayNode normalized = objectMapper.createArrayNode();

        for (JsonNode item : list) {
            if (!item.isString() || item.asString().isBlank()) {
                throw new BadRequestException("domainNames entries must be non-blank strings");
            }
            String domain = item.asString().trim();
            if (!seen.add(domain)) {
                throw new BadRequestException("Duplicate domainName in API Gateway targets: " + domain);
            }
            if (scopeDomains != null && !scopeDomains.contains(domain)) {
                throw new BadRequestException(
                        "domain '" + domain + "' is not in the credential's scope.customDomains");
            }
            normalized.add(domain);
        }

        ObjectNode root = objectMapper.createObjectNode();
        root.set("domainNames", normalized);
        return root;
    }

    /**
     * Reads the {@code customDomains} array from the credential's configJson (scope).
     * Returns null if not set (no guardrail — all domains accepted).
     */
    private Set<String> parseScopeCustomDomains(CredentialReferenceEntity credential) {
        String configJson = credential.getConfigJson();
        if (configJson == null || configJson.isBlank()) return null;
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode list = root.get("customDomains");
            if (list == null || !list.isArray() || list.isEmpty()) return null;
            Set<String> out = new LinkedHashSet<>();
            for (JsonNode item : list) {
                if (item.isString() && !item.asString().isBlank()) out.add(item.asString());
            }
            return out.isEmpty() ? null : out;
        } catch (Exception e) {
            log.warn("API Gateway credential configJson unparseable: {}", e.getMessage());
            return null;
        }
    }
}
