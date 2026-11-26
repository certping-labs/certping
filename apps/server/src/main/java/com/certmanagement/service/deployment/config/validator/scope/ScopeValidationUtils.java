// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.JsonNode;

import java.util.Set;

/** Shared helpers for {@code DeploymentScopeValidator} implementations. */
public final class ScopeValidationUtils {

    private ScopeValidationUtils() {}

    public static void requireObject(JsonNode configJson, String provider) {
        if (configJson == null || configJson.isNull()) {
            throw new BadRequestException(provider + " configJson is required");
        }
        if (!configJson.isObject()) {
            throw new BadRequestException(provider + " configJson must be a JSON object");
        }
    }

    public static String requireString(JsonNode configJson, String field, String provider) {
        JsonNode node = configJson.get(field);
        if (node == null || node.isNull() || !node.isString() || node.asString().isBlank()) {
            throw new BadRequestException(
                    provider + " configJson missing required string field: " + field);
        }
        return node.asString().trim();
    }

    public static String optionalString(JsonNode configJson, String field) {
        JsonNode node = configJson.get(field);
        if (node == null || node.isNull() || !node.isString()) return null;
        String s = node.asString();
        return s.isBlank() ? null : s.trim();
    }

    public static String requireOneOf(JsonNode configJson, String field, Set<String> allowed,
                                      String provider) {
        String value = requireString(configJson, field, provider);
        if (!allowed.contains(value)) {
            throw new BadRequestException(
                    provider + " configJson." + field + " must be one of " + allowed
                            + ", got: " + value);
        }
        return value;
    }

    public static String optionalOneOf(JsonNode configJson, String field, Set<String> allowed,
                                       String provider) {
        String value = optionalString(configJson, field);
        if (value == null) return null;
        if (!allowed.contains(value)) {
            throw new BadRequestException(
                    provider + " configJson." + field + " must be one of " + allowed
                            + " when present, got: " + value);
        }
        return value;
    }

    public static void requireNonEmptyArray(JsonNode configJson, String field, String provider) {
        JsonNode node = configJson.get(field);
        if (node == null || !node.isArray() || node.isEmpty()) {
            throw new BadRequestException(
                    provider + " configJson." + field + " must be a non-empty array");
        }
        int i = 0;
        for (JsonNode element : node) {
            if (!element.isString() || element.asString().isBlank()) {
                throw new BadRequestException(
                        provider + " configJson." + field + "[" + i + "] must be a non-blank string");
            }
            i++;
        }
    }

    public static Integer optionalInt(JsonNode configJson, String field, String provider) {
        JsonNode node = configJson.get(field);
        if (node == null || node.isNull()) return null;
        if (!node.isInt() && !node.canConvertToInt()) {
            throw new BadRequestException(
                    provider + " configJson." + field + " must be an integer when present");
        }
        return node.asInt();
    }

    public static Boolean optionalBoolean(JsonNode configJson, String field, String provider) {
        JsonNode node = configJson.get(field);
        if (node == null || node.isNull()) return null;
        if (!node.isBoolean()) {
            throw new BadRequestException(
                    provider + " configJson." + field + " must be a boolean when present");
        }
        return node.asBoolean();
    }
}
