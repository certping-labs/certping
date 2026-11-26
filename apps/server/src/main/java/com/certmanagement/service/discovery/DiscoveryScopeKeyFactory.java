// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class DiscoveryScopeKeyFactory {

    private final ObjectMapper objectMapper;

    public String create(Long organizationId, String targetType, String credentialXref, String scopeJson) {
        String canonicalScope = canonicalizeScope(scopeJson);
        String material = organizationId + "\n" + targetType + "\n" + credentialXref + "\n" + canonicalScope;
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private String canonicalizeScope(String scopeJson) {
        if (scopeJson == null || scopeJson.isBlank()) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(sortNode(objectMapper.readTree(scopeJson)));
        } catch (Exception exception) {
            throw new IllegalArgumentException("Discovery credential scope must be valid JSON", exception);
        }
    }

    private JsonNode sortNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode sorted = objectMapper.createObjectNode();
            List<String> fieldNames = new ArrayList<>();
            node.propertyNames().iterator().forEachRemaining(fieldNames::add);
            fieldNames.stream().sorted().forEach(name -> sorted.set(name, sortNode(node.get(name))));
            return sorted;
        }
        if (node.isArray()) {
            return node;
        }
        return node;
    }
}
