// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What a customer event is about. Each {@link AuditEventType} reads the fields its templates name;
 * the rest stay {@code null}.
 *
 * @param organizationId the trail the row lands in; {@code null} means the organization the actor acts
 *                       for. Set it when a super admin or a platform-wide job acts on a customer's
 *                       resource, so the row lands in that customer's trail
 * @param resourceId     the target's numeric id, when it has one
 * @param resourceRef    the target's stable string reference (an xref), when it has one
 * @param name           the target's display name, e.g. a credential's name. Never stored for
 *                       member-targeted events (see {@link AuditEventType#rendersTargetWhenRead()})
 * @param provider       the provider in words, e.g. "Azure", "Let's Encrypt"
 * @param domain         the domain the event concerns
 * @param count          how many items, for bulk events
 * @param format         an export or file format
 * @param enabled        the new state of an on/off setting
 * @param changes        the fields changed, with before and after
 * @param attributes     named values; only those on the event's allow-list are kept
 */
@Jacksonized
@Builder(toBuilder = true)
public record AuditSubject(
        Long organizationId,
        Long resourceId,
        String resourceRef,
        String name,
        String provider,
        String domain,
        Integer count,
        String format,
        Boolean enabled,
        List<AuditChange> changes,
        Map<String, String> attributes) {

    public static final AuditSubject NONE = AuditSubject.builder().build();

    public AuditSubject {
        changes = changes == null ? List.of() : List.copyOf(changes);
        if (attributes == null) {
            attributes = Map.of();
        } else {
            Map<String, String> copy = new LinkedHashMap<>();
            attributes.forEach((key, value) -> {
                if (key != null && value != null) {
                    copy.put(key, value);
                }
            });
            attributes = Collections.unmodifiableMap(copy);
        }
    }

    /** Whether an on/off subject is on; {@code null} reads as off. */
    public boolean isEnabled() {
        return Objects.equals(enabled, Boolean.TRUE);
    }
}
