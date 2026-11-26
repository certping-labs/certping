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
 * Validates {@code AZURE_APP_GW} deployment targets: {@code sslCertName} (per-cert AGW SSL cert
 * resource name + KV cert name) plus {@code listenerNames} array (subset of scope listeners).
 *
 * <p>{@code sslCertName} is required on first deploy; subsequent rotations lock it via
 * {@code result.certificateName} (operator edits to the value have no effect after first deploy).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureAppGatewayTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_APP_GW);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        if (requestedTargets == null || !requestedTargets.isObject()) {
            throw new BadRequestException("Azure App Gateway targets must be a JSON object");
        }
        JsonNode certNameNode = requestedTargets.get("sslCertName");
        if (certNameNode == null || !certNameNode.isString() || certNameNode.asString().isBlank()) {
            throw new BadRequestException("Azure App Gateway targets.sslCertName is required (non-blank string)");
        }
        String sslCertName = certNameNode.asString().trim();

        JsonNode listNode = requestedTargets.get("listenerNames");
        if (listNode == null || !listNode.isArray() || listNode.isEmpty()) {
            throw new BadRequestException("Azure App Gateway targets.listenerNames must be a non-empty array");
        }

        Set<String> scopeListeners = parseScopeListeners(credential);
        Set<String> seen = new LinkedHashSet<>();
        ArrayNode normalized = objectMapper.createArrayNode();

        for (JsonNode item : listNode) {
            if (!item.isString() || item.asString().isBlank()) {
                throw new BadRequestException("Listener names must be non-blank strings");
            }
            String name = item.asString().trim();
            if (!seen.add(name)) {
                throw new BadRequestException("Duplicate listener name: " + name);
            }
            if (scopeListeners != null && !scopeListeners.contains(name)) {
                throw new BadRequestException(
                        "listener '" + name + "' is not in the credential's scope.listeners");
            }
            normalized.add(name);
        }

        ObjectNode root = objectMapper.createObjectNode();
        root.put("sslCertName", sslCertName);
        root.set("listenerNames", normalized);
        return root;
    }

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
            log.warn("Azure App Gateway credential configJson unparseable: {}", e.getMessage());
            return null;
        }
    }
}
