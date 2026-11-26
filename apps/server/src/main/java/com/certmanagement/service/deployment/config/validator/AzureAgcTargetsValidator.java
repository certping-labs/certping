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
 * Validates {@code AZURE_APP_GW_CONTAINERS} deployment targets: {@code secrets[]} array
 * of {@code {namespace, secretName}} objects.
 *
 * <p>Each {@code namespace} must be in the credential scope's {@code secretNamespaces[]} array.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureAgcTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_APP_GW_CONTAINERS);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        if (requestedTargets == null || !requestedTargets.isObject()) {
            throw new BadRequestException("Azure AGC targets must be a JSON object");
        }
        JsonNode secretsNode = requestedTargets.get("secrets");
        if (secretsNode == null || !secretsNode.isArray() || secretsNode.isEmpty()) {
            throw new BadRequestException("Azure AGC targets.secrets must be a non-empty array");
        }

        Set<String> scopeNamespaces = parseScopeSecretNamespaces(credential);
        Set<String> seen = new LinkedHashSet<>();
        ArrayNode normalizedSecrets = objectMapper.createArrayNode();

        for (JsonNode item : secretsNode) {
            if (!item.isObject()) {
                throw new BadRequestException("Azure AGC secrets[] entries must be objects");
            }
            String namespace = requireText(item, "namespace");
            String secretName = requireText(item, "secretName");

            String key = namespace + "/" + secretName;
            if (!seen.add(key)) {
                throw new BadRequestException("Duplicate secret ref: " + key);
            }
            if (scopeNamespaces != null && !scopeNamespaces.contains(namespace)) {
                throw new BadRequestException(
                        "namespace '" + namespace + "' is not in the credential's scope.secretNamespaces");
            }

            ObjectNode normalized = objectMapper.createObjectNode();
            normalized.put("namespace", namespace);
            normalized.put("secretName", secretName);
            normalizedSecrets.add(normalized);
        }

        ObjectNode root = objectMapper.createObjectNode();
        root.set("secrets", normalizedSecrets);
        return root;
    }

    private String requireText(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || !v.isString() || v.asString().isBlank()) {
            throw new BadRequestException("Azure AGC secrets[]." + field + " must be a non-blank string");
        }
        return v.asString().trim();
    }

    private Set<String> parseScopeSecretNamespaces(CredentialReferenceEntity credential) {
        String configJson = credential.getConfigJson();
        if (configJson == null || configJson.isBlank()) return null;
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode list = root.get("secretNamespaces");
            if (list == null || !list.isArray() || list.isEmpty()) return null;
            Set<String> out = new LinkedHashSet<>();
            for (JsonNode item : list) {
                if (item.isString() && !item.asString().isBlank()) out.add(item.asString());
            }
            return out.isEmpty() ? null : out;
        } catch (Exception e) {
            log.warn("Azure AGC credential configJson unparseable: {}", e.getMessage());
            return null;
        }
    }
}
