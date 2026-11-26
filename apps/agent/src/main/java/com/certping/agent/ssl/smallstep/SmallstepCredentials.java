// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

record SmallstepCredentials(
        String baseUrl,
        String authorityName,
        String provisionerName,
        String provisionerPrivateJwk,
        String rootCaPem) {

    static SmallstepCredentials parse(String raw, ObjectMapper mapper, String baseUrlOverride) {
        if (raw == null || raw.isBlank()) {
            throw new PermanentAgentException("SMALLSTEP_CREDENTIAL_MISSING",
                    "Smallstep credential secret is empty");
        }
        try {
            JsonNode json = mapper.readTree(raw);
            String baseUrl = notBlank(baseUrlOverride) ? baseUrlOverride.trim() : text(json, "baseUrl");
            String authorityName = text(json, "authorityName");
            String provisionerName = text(json, "provisionerName");
            JsonNode jwkNode = json.get("provisionerPrivateJwk");
            String jwk = jwkNode == null || jwkNode.isNull() ? null
                    : jwkNode.isString() ? jwkNode.asString() : mapper.writeValueAsString(jwkNode);
            String root = text(json, "rootCaPem");
            require(baseUrl, "baseUrl");
            require(provisionerName, "provisionerName");
            require(jwk, "provisionerPrivateJwk");
            require(root, "rootCaPem");
            if (!baseUrl.startsWith("https://")) {
                throw new PermanentAgentException("SMALLSTEP_CREDENTIAL_INVALID",
                        "Smallstep baseUrl must use HTTPS");
            }
            return new SmallstepCredentials(stripSlash(baseUrl), authorityName,
                    provisionerName, jwk, root);
        } catch (PermanentAgentException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_CREDENTIAL_INVALID",
                    "Smallstep credential secret is invalid JSON", exception);
        }
    }

    @Override
    public String toString() {
        return "SmallstepCredentials[baseUrl=" + baseUrl + ", provisionerName="
                + provisionerName + ", secrets redacted]";
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || value.asString().isBlank()) return null;
        return value.asString();
    }
    private static void require(String value, String field) {
        if (!notBlank(value)) throw new PermanentAgentException("SMALLSTEP_CREDENTIAL_INVALID",
                "Smallstep credential is missing '" + field + "'");
    }
    private static boolean notBlank(String value) { return value != null && !value.isBlank(); }
    private static String stripSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
