// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.JacksonException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Component
public class CertificateProfileJsonCodec {
    private static final int MAX_JSON_BYTES = 64 * 1024;
    private static final Set<String> FORBIDDEN_FIELD_PARTS = Set.of(
            "password", "secret", "token", "challenge", "credential", "clientsecret",
            "email", "userid", "userprincipalname");

    private final ObjectMapper objectMapper;

    public CertificateProfileJsonCodec(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String writeSafe(Object value) {
        return writeSanitized(value, false, false);
    }

    /**
     * User-supplied profile JSON must fail closed when it contains a credential or
     * user-identity field. Silently deleting such a field would make the saved
     * profile differ from what the caller submitted.
     */
    public String writeRequest(Object value) {
        return writeSanitized(value, false, true);
    }

    /**
     * Provider payloads arrive asynchronously and must never poison a queued message.
     * Oversized snapshots retain a safe size marker while normalized configuration remains
     * available in the dedicated configuration table.
     */
    public String writeProviderSnapshot(Object value) {
        return writeSanitized(value, true, false);
    }

    String sha256(Object value) {
        try {
            byte[] serialized = objectMapper.writeValueAsBytes(value);
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(serialized));
        } catch (JacksonException | NoSuchAlgorithmException exception) {
            throw new IllegalArgumentException(
                    "Profile sync batch could not be checksummed", exception);
        }
    }

    private String writeSanitized(
            Object value, boolean truncateOversized, boolean rejectForbiddenFields) {
        try {
            JsonNode tree = objectMapper.valueToTree(value == null ? Map.of() : value);
            if (rejectForbiddenFields && containsForbiddenField(tree)) {
                throw new ResponseStatusException(
                        BAD_REQUEST, "Profile JSON contains a forbidden sensitive field");
            }
            JsonNode sanitized = sanitize(tree);
            byte[] bytes = objectMapper.writeValueAsBytes(sanitized);
            if (bytes.length > MAX_JSON_BYTES) {
                if (truncateOversized) {
                    return objectMapper.writeValueAsString(Map.of(
                            "truncated", true,
                            "sanitizedBytes", bytes.length));
                }
                throw new ResponseStatusException(BAD_REQUEST, "Profile JSON exceeds 64 KiB");
            }
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (JacksonException exception) {
            throw new ResponseStatusException(BAD_REQUEST, "Profile JSON is invalid", exception);
        }
    }

    public Map<String, Object> readObject(String value) {
        return read(value, new TypeReference<>() {}, Map.of());
    }

    public List<Map<String, Object>> readObjectList(String value) {
        return read(value, new TypeReference<>() {}, List.of());
    }

    public List<String> readStringList(String value) {
        return read(value, new TypeReference<>() {}, List.of());
    }

    private <T> T read(String value, TypeReference<T> type, T empty) {
        if (value == null || value.isBlank()) {
            return empty;
        }
        try {
            return objectMapper.readValue(value, type);
        } catch (JacksonException exception) {
            throw new IllegalStateException("Stored profile JSON is invalid", exception);
        }
    }

    private JsonNode sanitize(JsonNode node) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = object.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (isForbidden(field.getKey())) {
                    fields.remove();
                } else {
                    sanitize(field.getValue());
                }
            }
            return object;
        }
        if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) {
                ((tools.jackson.databind.node.ArrayNode) node).set(index, sanitize(node.get(index)));
            }
        }
        return node;
    }

    private boolean containsForbiddenField(JsonNode node) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (isForbidden(field.getKey()) || containsForbiddenField(field.getValue())) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                if (containsForbiddenField(child)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isForbidden(String field) {
        String normalized = field.replace("_", "").replace("-", "")
                .toLowerCase(Locale.ROOT);
        return FORBIDDEN_FIELD_PARTS.stream().anyMatch(normalized::contains);
    }
}
