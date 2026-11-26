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
import java.util.regex.Pattern;

/**
 * Validates {@code AWS_ALB} / {@code AWS_NLB} targets.
 *
 * <p>New flat shape: {@code { "listenerArns": [ "arn:..." ] }}.
 * One credential = one load balancer. The LB ARN and all available listeners live
 * in the credential scope ({@code configJson.loadBalancerArn}, {@code configJson.listeners}).
 * Targets select a subset of those listeners for this certificate.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AwsElbTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AWS_ALB, TargetType.AWS_NLB);
    private static final Pattern LISTENER_ARN_PATTERN =
            Pattern.compile("^arn:aws:elasticloadbalancing:[a-z0-9-]+:\\d{12}:listener/(app|net)/[^/]+/[^/]+/[^/]+$");

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        if (requestedTargets == null || !requestedTargets.isObject()) {
            throw new BadRequestException("AWS ELB targets must be a JSON object");
        }
        JsonNode list = requestedTargets.get("listenerArns");
        if (list == null || !list.isArray() || list.isEmpty()) {
            throw new BadRequestException("AWS ELB targets.listenerArns must be a non-empty array");
        }

        Set<String> scopeListeners = parseScopeListeners(credential);
        Set<String> seen = new LinkedHashSet<>();
        ArrayNode normalized = objectMapper.createArrayNode();

        for (JsonNode item : list) {
            if (!item.isString() || item.asString().isBlank()) {
                throw new BadRequestException("listenerArn entries must be non-blank strings");
            }
            String arn = item.asString().trim();
            if (!LISTENER_ARN_PATTERN.matcher(arn).matches()) {
                throw new BadRequestException("listenerArn does not match expected format: " + arn);
            }
            if (!seen.add(arn)) {
                throw new BadRequestException("Duplicate listenerArn: " + arn);
            }
            if (scopeListeners != null && !scopeListeners.contains(arn)) {
                throw new BadRequestException(
                        "listenerArn '" + arn + "' is not in the credential's scope.listeners");
            }
            normalized.add(arn);
        }

        ObjectNode root = objectMapper.createObjectNode();
        root.set("listenerArns", normalized);
        return root;
    }

    /**
     * Reads the {@code listeners} array from the credential's configJson (scope).
     * Returns null if not set (no guardrail — all listeners accepted).
     */
    private Set<String> parseScopeListeners(CredentialReferenceEntity credential) {
        String configJson = credential.getConfigJson();
        if (configJson == null || configJson.isBlank()) return null;
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode list = root.get("listeners");
            if (list == null || !list.isArray() || list.isEmpty()) return null;
            Set<String> out = new LinkedHashSet<>();
            for (JsonNode item : list) {
                if (item.isString() && !item.asString().isBlank()) out.add(item.asString());
            }
            return out.isEmpty() ? null : out;
        } catch (Exception e) {
            log.warn("AWS ELB credential configJson unparseable: {}", e.getMessage());
            return null;
        }
    }
}
