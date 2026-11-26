// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditAccessEntryDto;
import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditEventEntryDto.AuditChangeDto;
import com.certmanagement.dto.audit.AuditPlatformEntryDto;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.core.JacksonException;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * Renders loaded rows as the entries each view returns, the one place the read side names things
 * ({@link AuditDisplayNames}): the organization's and member target's live names, the requester of a system or
 * agent row ({@code requestedByName}), the actor's label, the failure reason's sentence. Every user and
 * organization of a batch is looked up in one query each, so a page, or an export chunk, costs the same
 * however many rows name them.
 *
 * <p>Masking: to a customer, a staff row (a super admin acting in their trail) reads as "Platform administrator", with
 * no user id, email, address or user agent, and a requester from outside the organization (a platform account)
 * reads the same. The platform view ({@link #platform}) masks nothing and adds the staff fields.
 */
final class AuditEntryRenderer {

    /** The attribute naming, by user id, who asked for a system or agent action. */
    static final String REQUESTED_BY = "requestedBy";

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();

    private final AuditEventQueryStore store;

    AuditEntryRenderer(AuditEventQueryStore store) {
        this.store = store;
    }

    /** The customer list's (and the platform's base) entries. */
    List<AuditEventEntryDto> activity(List<AuditEventRecord> rows, AuditVisibilityPolicy.Viewer viewer) {
        return render(rows, viewer, Rendered::entry);
    }

    /** The Access view's entries. */
    List<AuditAccessEntryDto> access(List<AuditEventRecord> rows, AuditVisibilityPolicy.Viewer viewer) {
        return render(rows, viewer, rendered -> {
            AuditEventEntryDto entry = rendered.entry();
            AuditEventRecord row = rendered.row();
            return AuditAccessEntryDto.builder()
                    .id(entry.id())
                    .timestamp(entry.timestamp())
                    .activity(entry.event())
                    .target(row.resourceName() != null && !row.resourceName().isBlank() ? entry.resourceName()
                            : row.resourceRef())
                    .resourceId(entry.resourceId())
                    .status(entry.status())
                    .errorCode(entry.errorCode())
                    .actor(entry.actorName())
                    .userId(entry.userId())
                    .userEmail(entry.userEmail())
                    .ipAddress(entry.ipAddress())
                    .requestId(entry.requestId())
                    .correlationId(entry.correlationId())
                    .summary(entry.summary())
                    .reason(entry.reason())
                    .userAgent(entry.userAgent())
                    .organizationId(entry.organizationId())
                    .build();
        });
    }

    /** The platform view's entries: unmasked, with the staff fields. Only for a super admin's viewer. */
    List<AuditPlatformEntryDto> platform(List<AuditEventRecord> rows, AuditVisibilityPolicy.Viewer viewer) {
        if (!viewer.superAdmin()) {
            throw new IllegalStateException("the platform view is a super admin's");
        }
        return render(rows, viewer, rendered -> {
            AuditEventRecord row = rendered.row();
            return new AuditPlatformEntryDto(rendered.entry(), row.visibility(), principal(row), row.actorStaff(),
                    row.authMethod(), row.traceId(), rendered.details().request());
        });
    }

    /** One row with what the batch looked up for it. */
    private record Rendered(AuditEventRecord row, Details details, AuditEventEntryDto entry) {
    }

    private <T> List<T> render(List<AuditEventRecord> rows, AuditVisibilityPolicy.Viewer viewer,
                               Function<Rendered, T> view) {
        Set<Integer> userIds = new HashSet<>();
        Set<Long> organizationIds = new HashSet<>();
        List<Details> details = new ArrayList<>(rows.size());
        Map<Long, Set<String>> featureKeys = new HashMap<>();
        for (AuditEventRecord row : rows) {
            Details parsed = details(row.details(), viewer.superAdmin());
            details.add(parsed);
            if (parsed.requestedBy() != null) {
                userIds.add(parsed.requestedBy());
            }
            if (row.actorUserId() != null && !masked(row, viewer)) {
                userIds.add(row.actorUserId());
            }
            Integer member = memberTarget(row);
            if (member != null) {
                userIds.add(member);
            }
            if (row.organizationId() != null) {
                organizationIds.add(row.organizationId());
                if (row.featureKey() != null) {
                    featureKeys.computeIfAbsent(row.organizationId(), org -> new HashSet<>()).add(row.featureKey());
                }
            }
        }
        viewer.prefetch(featureKeys);
        Map<Integer, AuditEventQueryStore.LiveUser> users = store.users(userIds);
        Map<Long, String> organizations = store.organizationNames(organizationIds);
        List<T> entries = new ArrayList<>(rows.size());
        for (int i = 0; i < rows.size(); i++) {
            AuditEventRecord row = rows.get(i);
            Details parsed = details.get(i);
            entries.add(view.apply(new Rendered(row, parsed,
                    entry(row, parsed, viewer, users, organizations, masked(row, viewer)))));
        }
        return entries;
    }

    private static AuditEventEntryDto entry(AuditEventRecord row, Details details, AuditVisibilityPolicy.Viewer viewer,
                                            Map<Integer, AuditEventQueryStore.LiveUser> users,
                                            Map<Long, String> organizations, boolean masked) {
        Integer userId = masked ? null : row.actorUserId();
        AuditEventQueryStore.LiveUser actor = AuditEventQueryStore.LiveUser.live(users, userId);
        String summary = row.summary();
        String resourceName = row.resourceName();
        Integer member = memberTarget(row);
        if (isMemberTargeted(row) && member == null) {
            summary = AuditDisplayNames.unidentifiedMemberSummary(summary);
        } else if (isMemberTargeted(row)) {
            AuditEventQueryStore.LiveUser target = AuditEventQueryStore.LiveUser.live(users, member);
            String liveName = target == null ? null : target.name();
            summary = AuditDisplayNames.memberSummary(summary, liveName);
            resourceName = liveName;
        }
        String organizationName = null;
        if (row.organizationId() != null) {
            String live = organizations.get(row.organizationId());
            organizationName = viewer.superAdmin()
                    ? AuditDisplayNames.organizationForPlatform(row.organizationId(), live)
                    : AuditDisplayNames.organization(live);
        }
        return AuditEventEntryDto.builder()
                .id(row.id())
                .userId(userId)
                .userEmail(actor == null ? null : actor.email())
                .organizationId(row.organizationId())
                .organizationName(organizationName)
                .action(row.action())
                .resource(row.resourceType())
                .resourceId(row.resourceId())
                .status(row.outcome())
                .details(details.json())
                .ipAddress(masked ? null : row.ipAddress())
                .timestamp(OffsetDateTime.ofInstant(row.occurredAt(), ZoneOffset.UTC))
                .event(row.event())
                .summary(summary)
                .resourceName(resourceName)
                .actorType(row.actorType())
                .actorName(masked ? AuditDisplayNames.STAFF : AuditDisplayNames.actor(actorType(row.actorType()),
                        row.actorUserId(), row.actorLabel()))
                .errorCode(row.errorCode())
                .requestId(row.requestId())
                .correlationId(row.correlationId())
                .changes(details.changes())
                .category(row.category())
                .resourceRef(row.resourceRef())
                .reason(row.errorCode() == null ? null : AuditReason.of(row.errorCode()).message(row.requestId()))
                .userAgent(masked ? null : row.userAgent())
                .featureOff(viewer.featureOff(row.organizationId(), row.featureKey()))
                .requestedByName(requester(row, details, viewer, users, masked))
                .build();
    }

    /**
     * Who asked for a system or agent row ({@code attributes.requestedBy}): their live name, else "a former
     * member". To a customer, a staff row's requester, or a requester who holds the platform's SUPER_ADMIN role,
     * is Platform administrator; anyone else is named, whatever organization they are in now.
     */
    private static String requester(AuditEventRecord row, Details details, AuditVisibilityPolicy.Viewer viewer,
                                    Map<Integer, AuditEventQueryStore.LiveUser> users, boolean masked) {
        if (details.requestedBy() == null) {
            return null;
        }
        if (masked) {
            return AuditDisplayNames.STAFF;
        }
        AuditEventQueryStore.LiveUser requester = users.get(details.requestedBy());
        if (requester != null && !viewer.superAdmin() && requester.superAdmin()) {
            return AuditDisplayNames.STAFF;
        }
        AuditEventQueryStore.LiveUser named = AuditEventQueryStore.LiveUser.live(users, details.requestedBy());
        return AuditDisplayNames.requester(named == null ? null : named.name());
    }

    /**
     * A staff row ({@code actor_staff}, decided when it was written: {@link AuditEvents}, {@link AuditEventStore})
     * reads to a customer as Platform administrator, with nothing of who or from where.
     */
    private static boolean masked(AuditEventRecord row, AuditVisibilityPolicy.Viewer viewer) {
        return row.actorStaff() && !viewer.superAdmin();
    }

    /** The actor as one stable string: user:42, system:job, anonymous. */
    private static String principal(AuditEventRecord row) {
        return switch (actorType(row.actorType())) {
            case USER -> row.actorUserId() == null ? "user" : "user:" + row.actorUserId();
            case API_TOKEN -> "api_token";
            case SYSTEM -> row.actorJob() == null || row.actorJob().isBlank() ? "system" : "system:" + row.actorJob();
            case ANONYMOUS -> "anonymous";
        };
    }

    /** Member-targeted rows store no name; it is rendered from the live users row. */
    private static boolean isMemberTargeted(AuditEventRecord row) {
        return "USER".equals(row.resourceType());
    }

    private static Integer memberTarget(AuditEventRecord row) {
        if (!isMemberTargeted(row)) {
            return null;
        }
        if (row.resourceId() != null) {
            return row.resourceId() > 0 && row.resourceId() <= Integer.MAX_VALUE ? row.resourceId().intValue() : null;
        }
        if (row.resourceRef() != null && row.resourceRef().matches("\\d{1,9}")) {
            return Integer.valueOf(row.resourceRef());
        }
        return null;
    }

    private static AuditActorType actorType(String stored) {
        try {
            return AuditActorType.valueOf(stored);
        } catch (IllegalArgumentException | NullPointerException unknown) {
            return AuditActorType.ANONYMOUS;
        }
    }

    /**
     * @param requestedBy the user id in {@code attributes.requestedBy}, when it is one
     * @param request     the request of an {@code api.request} row (platform view only)
     */
    private record Details(String json, List<AuditChangeDto> changes, Integer requestedBy,
                           AuditPlatformEntryDto.RequestInfo request) {
        static final Details NONE = new Details(null, List.of(), null, null);
    }

    /**
     * The stored {@code {"kind":"event","changes":[...],"attributes":{...}}} as the reader sees it: a JSON
     * string with the attributes and changes (the shape the app's {@code readDetailAttributes} parses), the
     * changes as a list, and the requester's id. The raw requester id is left out of a customer's JSON;
     * they read the requester by name ({@code requestedByName}).
     */
    private static Details details(String stored, boolean superAdmin) {
        if (stored == null || stored.isBlank()) {
            return Details.NONE;
        }
        JsonNode node;
        try {
            node = JSON.readTree(stored);
        } catch (JacksonException unreadable) {
            return Details.NONE;
        }
        if (node == null || !node.isObject()) {
            return Details.NONE;
        }
        ObjectNode shown = JSON.createObjectNode();
        Integer requestedBy = null;
        AuditPlatformEntryDto.RequestInfo request = null;
        JsonNode attributes = node.get("attributes");
        if (attributes != null && attributes.isObject()) {
            ObjectNode kept = (ObjectNode) attributes.deepCopy();
            JsonNode requester = kept.get(REQUESTED_BY);
            if (requester != null) {
                String id = requester.asString("");
                requestedBy = id.matches("\\d{1,9}") ? Integer.valueOf(id) : null;
                if (!superAdmin) {
                    kept.remove(REQUESTED_BY);
                }
            }
            if (superAdmin && kept.hasNonNull("method") && kept.hasNonNull("route")) {
                request = new AuditPlatformEntryDto.RequestInfo(kept.get("method").asString(),
                        kept.get("route").asString(), number(kept.get("status")), longNumber(kept.get("durationMs")));
            }
            if (!kept.isEmpty()) {
                shown.set("attributes", kept);
            }
        }
        List<AuditChangeDto> changes = new ArrayList<>();
        JsonNode storedChanges = node.get("changes");
        if (storedChanges != null && storedChanges.isArray() && !storedChanges.isEmpty()) {
            shown.set("changes", storedChanges);
            for (JsonNode change : storedChanges) {
                changes.add(new AuditChangeDto(textOf(change, "field"), textOf(change, "before"),
                        textOf(change, "after")));
            }
        }
        try {
            return new Details(shown.isEmpty() ? null : JSON.writeValueAsString(shown), List.copyOf(changes),
                    requestedBy, request);
        } catch (JacksonException e) {
            throw new IllegalStateException("audit details could not be serialised", e);
        }
    }

    private static Integer number(JsonNode value) {
        Long n = longNumber(value);
        return n == null || n > Integer.MAX_VALUE || n < Integer.MIN_VALUE ? null : n.intValue();
    }

    private static Long longNumber(JsonNode value) {
        if (value == null || value.isNull()) {
            return null;
        }
        String text = value.asString("").trim();
        return text.matches("-?\\d{1,18}") ? Long.valueOf(text) : null;
    }

    private static String textOf(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asString();
    }
}
