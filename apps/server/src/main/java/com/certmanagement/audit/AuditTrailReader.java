// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditAccessEntryDto;
import com.certmanagement.dto.audit.AuditAccessFilterRequest;
import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditEventPageResponse;
import com.certmanagement.dto.audit.AuditPlatformEntryDto;
import com.certmanagement.dto.audit.AuditPlatformFilterRequest;
import com.certmanagement.dto.audit.AuditTrailPage;
import com.certmanagement.exception.BadRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.regex.Pattern;

/**
 * Answers the audit trail's views from {@code audit_events}: the customer list
 * ({@code GET /api/v1/audit-logs}), the Access view
 * ({@code /access}) and the platform view ({@code GET /api/v1/admin/audit-logs}).
 *
 * <ul>
 *   <li><b>Window.</b> Customers see {@code certping.audit.customer-visible-days} (90) back: an earlier
 *       {@code from} is clamped silently, a range entirely before the window is an empty page, and the page
 *       says where the window starts ({@code visibleFrom}). Super admins on the customer routes are not clamped
 *       (the old audit page reads any organization's whole trail through them). The platform view is not
 *       clamped either (retention bounds it), but one query spans at most
 *       {@link #MAX_RANGE}, defaulting to the 90 days before {@code to}; a request or correlation id search
 *       across every organization spans at most {@link #MAX_ID_SEARCH_RANGE} (no index serves
 *       those ids, so the range bounds the scan).</li>
 *   <li><b>Paging.</b> Newest first by {@code (occurred_at, id)}; {@code timestamp,asc} is the only other
 *       order. {@code nextCursor} pages by keyset, so later pages cost the same as the first and stay stable
 *       when rows share a timestamp; the total is counted once and carried in the cursor. {@code page} is
 *       still accepted by the customer list as a bounded offset for the old page: never with a cursor, and
 *       never past the count cap.</li>
 *   <li><b>Total.</b> Counted up to {@code certping.audit.count-cap} (10,000; "N+" past it) with a
 *       {@code count-timeout-ms} budget; a count that times out degrades to a lower bound
 *       ({@link AuditEventQueryStore#countUpTo}). The rows query timing out is a 503 {@code QUERY_TIMEOUT}.</li>
 *   <li><b>Rendering.</b> {@link AuditEntryRenderer}: live names, staff masking for customers, the platform's
 *       staff fields.</li>
 *   <li><b>Features that are off.</b> {@link AuditVisibilityPolicy}: their rows stay listed, marked
 *       {@code featureOff}.</li>
 *   <li><b>Sensitive reads.</b> {@link AuditCategory#ACCESS} rows are left out of the list unless
 *       {@code category=ACCESS} asks for them; the Access view lists only them ({@link AuditTrailView}).</li>
 * </ul>
 */
@Service
public class AuditTrailReader {

    public static final int DEFAULT_PAGE_SIZE = 20;
    public static final int MAX_PAGE_SIZE = 100;
    /** The longest range one platform query or export spans: older periods are read in 90-day chunks. */
    public static final Duration MAX_RANGE = Duration.ofDays(90);
    /** The longest range a request or correlation id search across every organization spans. */
    public static final Duration MAX_ID_SEARCH_RANGE = Duration.ofDays(7);

    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,63}$");
    private static final Pattern EVENT = Pattern.compile("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$");
    private static final int MAX_TEXT = 256;

    private final AuditEventQueryStore store;
    private final AuditEntryRenderer renderer;
    private final Clock clock;
    private final int countCap;
    private final Duration customerVisible;

    public AuditTrailReader(AuditEventQueryStore store, Clock clock,
                            @Value("${certping.audit.count-cap:10000}") int countCap,
                            @Value("${certping.audit.customer-visible-days:90}") int customerVisibleDays) {
        if (countCap < 1) {
            throw new IllegalArgumentException("certping.audit.count-cap must be positive, was " + countCap);
        }
        if (customerVisibleDays < 1) {
            throw new IllegalArgumentException(
                    "certping.audit.customer-visible-days must be positive, was " + customerVisibleDays);
        }
        this.store = store;
        this.renderer = new AuditEntryRenderer(store);
        this.clock = clock;
        this.countCap = countCap;
        this.customerVisible = Duration.ofDays(customerVisibleDays);
    }

    /**
     * One page of the customer list {@code viewer} reads.
     *
     * @param page      the legacy offset page, or {@code null}; refused with a cursor
     * @param size      entries per page; defaults to 20, at most 100
     * @param ascending oldest first; ignored with a cursor, which keeps the order it was made for
     */
    @Transactional(readOnly = true)
    public AuditEventPageResponse read(AuditEventFilterRequest filter, Integer page, Integer size, boolean ascending,
                                       AuditVisibilityPolicy.Viewer viewer) {
        Paged<AuditEventEntryDto> paged = paged(AuditTrailView.ACTIVITY, filter, null, page, size, ascending, viewer,
                renderer::activity);
        return new AuditEventPageResponse(paged.content(), paged.number(), paged.size(), paged.total(),
                paged.totalPages(), paged.number() == 0, paged.last(), paged.content().size(),
                paged.content().isEmpty(), paged.capped(), paged.next(), utc(paged.visibleFrom()));
    }

    /**
     * One page of the Access view: the organization's sensitive reads only, under the list's window, cursor and
     * count. {@code activity} must be one of the catalog's reads.
     */
    @Transactional(readOnly = true)
    public AuditTrailPage<AuditAccessEntryDto> readAccess(AuditAccessFilterRequest filter, Integer size,
                                                          AuditVisibilityPolicy.Viewer viewer) {
        return paged(AuditTrailView.ACCESS, accessFilter(filter), null, null, size, false, viewer, renderer::access)
                .page();
    }

    /**
     * One page of the platform view: rows of either visibility (or the one asked for), of the organization the
     * super admin names or of all. Unclamped, at most {@link #MAX_RANGE} per query.
     */
    @Transactional(readOnly = true)
    public AuditTrailPage<AuditPlatformEntryDto> readPlatform(AuditPlatformFilterRequest filter, Integer size,
                                                              AuditVisibilityPolicy.Viewer viewer) {
        requireSuperAdmin(viewer);
        return paged(AuditTrailView.PLATFORM, filter, visibility(filter), null, size, false, viewer,
                renderer::platform).page();
    }

    /** The renderer the exporter renders its chunks with, as the pages are rendered. */
    AuditEntryRenderer renderer() {
        return renderer;
    }

    /**
     * A view's query, resolved and validated as a page's is, and where its window starts.
     *
     * @param empty the range lies entirely before the visible window: nothing may be read
     */
    record Resolved(AuditEventQuery query, Instant visibleFrom, boolean empty) {
    }

    /**
     * Resolves a view's filters into its query, as the pages do.
     *
     * @param clamp whether the customer window applies (customer views: always for an export; for a page, unless a
     *              super admin reads); ignored by the platform view, which is never clamped
     */
    Resolved resolve(AuditTrailView view, AuditEventFilterRequest filter, AuditVisibility visibility,
                     AuditVisibilityPolicy.Viewer viewer, boolean ascending, boolean clamp) {
        Instant from = filter.getFrom() == null ? null : filter.getFrom().toInstant();
        Instant to = filter.getTo() == null ? null : filter.getTo().toInstant();
        if (from != null && to != null && from.isAfter(to)) {
            throw new BadRequestException("from must not be after to");
        }
        AuditEventQuery query = query(filter, viewer, ascending).toBuilder().view(view).visibility(visibility).build();
        Instant visibleFrom = null;
        if (view == AuditTrailView.PLATFORM) {
            boolean idSearch = viewer.organizationId() == null
                    && (query.requestId() != null || query.correlationId() != null);
            Duration longest = idSearch ? MAX_ID_SEARCH_RANGE : MAX_RANGE;
            to = to == null ? clock.instant() : to;
            from = from == null ? to.minus(longest) : from;
            if (from.isAfter(to)) {
                throw new BadRequestException("from must not be after to");
            }
            if (Duration.between(from, to).compareTo(longest) > 0) {
                throw new BadRequestException(idSearch
                        ? "A request or correlation id search across all organizations covers at most 7 days: "
                                + "name the organization, or narrow the date range"
                        : "The date range is at most 90 days: read or export older periods in 90-day chunks");
            }
        } else if (clamp) {
            visibleFrom = clock.instant().minus(customerVisible).truncatedTo(ChronoUnit.SECONDS);
            if (from == null || from.isBefore(visibleFrom)) {
                from = visibleFrom;
            }
        }
        boolean empty = from != null && to != null && to.isBefore(from);
        return new Resolved(query.toBuilder().from(from).to(to).build(), visibleFrom, empty);
    }

    /** The Access view's filters as the list's: the kind of read must be one of the catalog's. */
    static AuditEventFilterRequest accessFilter(AuditAccessFilterRequest access) {
        AuditEventFilterRequest filter = access.toEventFilter();
        String activity = text("activity", filter.getEvent(), 64);
        if (activity != null && AuditEventType.byKey(activity)
                .filter(event -> event.category() == AuditCategory.ACCESS).isEmpty()) {
            throw new BadRequestException("Unknown activity: " + activity + "; see /access/activities");
        }
        return filter;
    }

    /** The platform view's visibility filter: CUSTOMER, INTERNAL, or both when none. */
    static AuditVisibility visibility(AuditPlatformFilterRequest filter) {
        return named("visibility", filter.getVisibility(), AuditVisibility.class);
    }

    static void requireSuperAdmin(AuditVisibilityPolicy.Viewer viewer) {
        if (!viewer.superAdmin()) {
            throw new IllegalStateException("the platform view is a super admin's");
        }
    }

    // ── Paging ───────────────────────────────────────────────────────────

    /** A page before it is shaped as a view's response. */
    private record Paged<T>(List<T> content, int number, int size, long total, boolean capped, boolean last,
                            String next, Instant visibleFrom) {

        int totalPages() {
            return (int) Math.min(Integer.MAX_VALUE, (total + size - 1) / size);
        }

        AuditTrailPage<T> page() {
            return new AuditTrailPage<>(content, number, size, total, totalPages(), number == 0, last, content.size(),
                    content.isEmpty(), capped, next, utc(visibleFrom));
        }
    }

    private <T> Paged<T> paged(AuditTrailView view, AuditEventFilterRequest filter, AuditVisibility visibility,
                               Integer page, Integer size, boolean ascending, AuditVisibilityPolicy.Viewer viewer,
                               BiFunction<List<AuditEventRecord>, AuditVisibilityPolicy.Viewer, List<T>> render) {
        int pageSize = size == null || size <= 0 ? DEFAULT_PAGE_SIZE : Math.min(size, MAX_PAGE_SIZE);
        String rawCursor = text("cursor", filter.getCursor(), 4096);
        if (rawCursor != null && page != null) {
            throw new BadRequestException("Pass either cursor or page, not both: follow nextCursor from page 0");
        }
        if (page != null && page < 0) {
            throw new BadRequestException("page must not be negative");
        }
        if (page != null && (long) page * pageSize > countCap) {
            throw new BadRequestException("page " + page + " lies past the first " + countCap
                    + " entries; narrow the filters or follow nextCursor instead");
        }
        AuditCursor cursor = rawCursor == null ? null : AuditCursor.decode(rawCursor);
        Resolved resolved = resolve(view, filter, visibility, viewer, cursor != null ? cursor.ascending() : ascending,
                !viewer.superAdmin());
        if (resolved.empty()) {
            // Entirely before the window: nothing in it may be shown.
            int number = cursor == null ? (page == null ? 0 : page) : cursor.number();
            return new Paged<>(List.of(), number, pageSize, 0, false, true, null, resolved.visibleFrom());
        }
        return cursor != null
                ? afterCursor(resolved, cursor, pageSize, viewer, render)
                : atOffset(resolved, page == null ? 0 : page, pageSize, viewer, render);
    }

    private <T> Paged<T> afterCursor(Resolved resolved, AuditCursor cursor, int size,
                                     AuditVisibilityPolicy.Viewer viewer,
                                     BiFunction<List<AuditEventRecord>, AuditVisibilityPolicy.Viewer, List<T>> render) {
        AuditEventQuery query = resolved.query();
        List<AuditEventRecord> rows = store.list(query,
                new AuditEventQueryStore.Keyset(cursor.at(), cursor.id()), 0, size + 1);
        boolean more = rows.size() > size;
        rows = more ? rows.subList(0, size) : rows;
        String next = more ? AuditCursor.after(rows.get(rows.size() - 1), cursor.number() + 1, cursor.total(),
                cursor.capped(), query.ascending()).encode() : null;
        return new Paged<>(render.apply(rows, viewer), cursor.number(), size, cursor.total(), cursor.capped(), !more,
                next, resolved.visibleFrom());
    }

    private <T> Paged<T> atOffset(Resolved resolved, int number, int size, AuditVisibilityPolicy.Viewer viewer,
                                  BiFunction<List<AuditEventRecord>, AuditVisibilityPolicy.Viewer, List<T>> render) {
        AuditEventQuery query = resolved.query();
        long offset = (long) number * size;
        // Rows past the cap are not served by offset (the cursor goes on past it).
        int limit = (int) Math.max(0, Math.min(size, countCap - offset));
        List<AuditEventRecord> rows = limit == 0 ? List.of() : store.list(query, null, offset, limit + 1);
        boolean more = rows.size() > limit;
        rows = more ? rows.subList(0, limit) : rows;

        long total;
        boolean capped;
        if (!more && (offset == 0 || !rows.isEmpty())) {
            // The last page: its total is exact without a count.
            total = offset + rows.size();
            capped = false;
        } else {
            OptionalLong counted = store.countUpTo(query, countCap + 1);
            if (counted.isEmpty()) {
                // A lower bound that keeps "next" enabled while there is more.
                total = Math.min(offset + rows.size() + (more ? 1 : 0), countCap);
                capped = true;
            } else {
                total = Math.min(counted.getAsLong(), countCap);
                capped = counted.getAsLong() > countCap;
            }
        }
        String next = more && !rows.isEmpty() ? AuditCursor.after(rows.get(rows.size() - 1), number + 1, total, capped,
                query.ascending()).encode() : null;
        // The old page cannot page by offset past the cap, so its last offset page is the last.
        boolean last = !more || offset + size >= countCap;
        return new Paged<>(render.apply(rows, viewer), number, size, total, capped, last, next,
                resolved.visibleFrom());
    }

    private AuditEventQuery query(AuditEventFilterRequest filter, AuditVisibilityPolicy.Viewer viewer,
                                  boolean ascending) {
        String action = code("action", filter.getAction());
        Set<String> events = null;
        String event = text("event", filter.getEvent(), 64);
        if (event != null) {
            if (!EVENT.matcher(event).matches()) {
                throw new BadRequestException("event must be an event key such as credential.deleted");
            }
            events = Set.of(event);
        }
        return AuditEventQuery.builder()
                .superAdmin(viewer.superAdmin())
                .organizationId(viewer.organizationId())
                .userId(filter.getUserId())
                .actorType(named("actorType", filter.getActorType(), AuditActorType.class))
                .action(action)
                .events(events)
                .category(named("category", filter.getCategory(), AuditCategory.class))
                .resourceType(code("resourceType", filter.getResourceType()))
                .resourceId(filter.getResourceId())
                .resourceRef(text("resourceRef", filter.getResourceRef(), MAX_TEXT))
                .resourceName(text("resourceName", filter.getResourceName(), MAX_TEXT))
                .outcome(outcome(filter))
                .requestId(text("requestId", filter.getRequestId(), MAX_TEXT))
                .correlationId(text("correlationId", filter.getCorrelationId(), MAX_TEXT))
                .hiddenFeatureKeys(viewer.hiddenFeatureKeys())
                .ascending(ascending)
                .build();
    }

    // ── Pages ────────────────────────────────────────────────────────────

    private static OffsetDateTime utc(Instant instant) {
        return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    // ── Validation ───────────────────────────────────────────────────────

    private static AuditOutcome outcome(AuditEventFilterRequest filter) {
        AuditOutcome status = named("status", filter.getStatus(), AuditOutcome.class);
        AuditOutcome outcome = named("outcome", filter.getOutcome(), AuditOutcome.class);
        if (status != null && outcome != null && status != outcome) {
            throw new BadRequestException("status and outcome disagree; pass one of them");
        }
        return outcome != null ? outcome : status;
    }

    private static <E extends Enum<E>> E named(String parameter, String value, Class<E> type) {
        String text = text(parameter, value, 64);
        if (text == null) {
            return null;
        }
        try {
            return Enum.valueOf(type, text.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            throw new BadRequestException("Unknown " + parameter + ": " + text);
        }
    }

    private static String code(String parameter, String value) {
        String text = text(parameter, value, 64);
        if (text == null) {
            return null;
        }
        String upper = text.toUpperCase(Locale.ROOT);
        if (!CODE.matcher(upper).matches()) {
            throw new BadRequestException(parameter + " must be a code such as DELETE");
        }
        return upper;
    }

    private static String text(String parameter, String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.length() > max) {
            throw new BadRequestException(parameter + " is longer than " + max + " characters");
        }
        return trimmed;
    }
}
