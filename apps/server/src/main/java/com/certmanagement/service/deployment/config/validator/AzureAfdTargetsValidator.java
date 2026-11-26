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
 * Validates {@code AZURE_AFD} deployment targets: {@code certificateName} (KV cert name)
 * + {@code secretName} (AFD Secret resource name on the profile) + {@code domainNames}.
 *
 * <p>{@code certificateName} and {@code secretName} are required on first deploy; subsequent
 * rotations lock them via {@code result.certificateName} / {@code result.secretName} so the
 * same KV cert and AFD Secret resource are reused (avoids orphaning resources).
 *
 * <p>Each domain name must be in the credential scope's {@code customDomains[]} array.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureAfdTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_AFD);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        if (requestedTargets == null || !requestedTargets.isObject()) {
            throw new BadRequestException("Azure AFD targets must be a JSON object");
        }
        JsonNode certNameNode = requestedTargets.get("certificateName");
        if (certNameNode == null || !certNameNode.isString() || certNameNode.asString().isBlank()) {
            throw new BadRequestException("Azure AFD targets.certificateName is required (non-blank string)");
        }
        String certificateName = certNameNode.asString().trim();

        JsonNode secretNameNode = requestedTargets.get("secretName");
        if (secretNameNode == null || !secretNameNode.isString() || secretNameNode.asString().isBlank()) {
            throw new BadRequestException("Azure AFD targets.secretName is required (non-blank string)");
        }
        String secretName = secretNameNode.asString().trim();

        JsonNode listNode = requestedTargets.get("domainNames");
        if (listNode == null || !listNode.isArray() || listNode.isEmpty()) {
            throw new BadRequestException("Azure AFD targets.domainNames must be a non-empty array");
        }

        Set<String> scopeDomains = parseScopeCustomDomains(credential);
        Set<String> seen = new LinkedHashSet<>();
        ArrayNode normalized = objectMapper.createArrayNode();

        for (JsonNode item : listNode) {
            if (!item.isString() || item.asString().isBlank()) {
                throw new BadRequestException("Domain names must be non-blank strings");
            }
            String name = item.asString().trim();
            if (!seen.add(name)) {
                throw new BadRequestException("Duplicate domain name: " + name);
            }
            if (scopeDomains != null && !scopeDomains.contains(name)) {
                throw new BadRequestException(
                        "domain '" + name + "' is not in the credential's scope.customDomains");
            }
            normalized.add(name);
        }

        ObjectNode root = objectMapper.createObjectNode();
        root.put("certificateName", certificateName);
        root.put("secretName", secretName);
        root.set("domainNames", normalized);
        return root;
    }

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
            log.warn("Azure AFD credential configJson unparseable: {}", e.getMessage());
            return null;
        }
    }
}
