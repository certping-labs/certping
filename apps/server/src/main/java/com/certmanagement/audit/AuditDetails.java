// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The typed details of a row: the fields a change touched, and named values the event's catalog entry
 * allows. Stored as {@code {"kind":"event","changes":[...],"attributes":{...}}}, and {@code NULL}
 * when both are empty. Never a free-form map: what a row can
 * carry is decided by {@link AuditEventType#allowedAttributes()}.
 */
public record AuditDetails(List<AuditChange> changes, Map<String, String> attributes) {

    public static final AuditDetails NONE = new AuditDetails(List.of(), Map.of());

    public AuditDetails {
        changes = changes == null ? List.of() : List.copyOf(changes);
        attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    public boolean isEmpty() {
        return changes.isEmpty() && attributes.isEmpty();
    }
}
