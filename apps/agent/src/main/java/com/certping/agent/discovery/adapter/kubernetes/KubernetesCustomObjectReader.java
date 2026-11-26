// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

final class KubernetesCustomObjectReader {

    private KubernetesCustomObjectReader() {
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> items(Object result) {
        if (!(result instanceof Map<?, ?> root) || !(root.get("items") instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                items.add((Map<String, Object>) map);
            }
        }
        return items;
    }

    @SuppressWarnings("unchecked")
    static String continueToken(Object result) {
        if (!(result instanceof Map<?, ?> root)
                || !(root.get("metadata") instanceof Map<?, ?> metadata)) {
            return null;
        }
        Object token = ((Map<String, Object>) metadata).get("continue");
        return token instanceof String string ? string : null;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> listAt(Map<String, Object> root, String... path) {
        Object value = valueAt(root, path);
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> values = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                values.add((Map<String, Object>) map);
            }
        }
        return values;
    }

    static List<String> stringsAt(Map<String, Object> root, String... path) {
        Object value = valueAt(root, path);
        if (!(value instanceof Collection<?> collection)) {
            return List.of();
        }
        return collection.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .sorted()
                .toList();
    }

    static String stringAt(Map<String, Object> root, String... path) {
        Object value = valueAt(root, path);
        return value instanceof String string ? string : null;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> mapAt(Map<String, Object> root, String... path) {
        Object value = valueAt(root, path);
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    static Integer intAt(Map<String, Object> root, String... path) {
        Object value = valueAt(root, path);
        return value instanceof Number number ? number.intValue() : null;
    }

    @SuppressWarnings("unchecked")
    private static Object valueAt(Map<String, Object> root, String... path) {
        Object current = root;
        for (String segment : path) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = ((Map<String, Object>) map).get(segment);
        }
        return current;
    }
}
