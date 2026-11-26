// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.exception.SqlStates;
import com.certmanagement.dto.audit.AuditAccessFilterRequest;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditPlatformFilterRequest;
import com.certmanagement.exception.AuditExportRefusedException;
import com.certmanagement.exception.BadRequestException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.StreamWriteFeature;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Exports the trail's views as CSV or JSON.
 *
 * <ul>
 *   <li><b>Recorded first.</b> A customer export writes its own row ({@code audit_log.exported},
 *       {@code access_log.exported}) in a transaction of its own before any of its rows is read, under the
 *       organization's export lock; if that row cannot be written the export is refused (503
 *       {@code EXPORT_NOT_RECORDED}): a read of the trail never happens unrecorded. A support export from the
 *       platform view writes {@code support.audit_log_exported} into the organization's trail the same way.</li>
 *   <li><b>Limits.</b> At most {@code certping.audit.export-max-rows} (10,000) rows: a larger export is refused
 *       (400 {@code EXPORT_TOO_LARGE}) and, for a customer, recorded as a failed export. An organization makes at
 *       most {@code certping.audit.exports-per-hour} (10) exports an hour, refused or not (429
 *       {@code EXPORT_LIMIT} with {@code Retry-After}). The count is of the export rows themselves, so every pod
 *       shares it without Redis, and the lock keeps two exports from both taking the last slot. Support exports
 *       have no hourly limit.</li>
 *   <li><b>Window.</b> Customer exports are clamped to the visible window, for super admins too (support exports
 *       older periods from the platform view, 90 days at a time). The window's end is fixed when the export is
 *       recorded, so the rows streamed are the rows counted.</li>
 *   <li><b>Streaming.</b> The rows are read through a cursor in a read-only transaction,
 *       {@value AuditEventQueryStore#EXPORT_FETCH_SIZE} at a time, rendered and written chunk by chunk
 *       ({@link AuditEventQueryStore#stream}); an export never holds more than one chunk.</li>
 *   <li><b>Resources.</b> At most {@code certping.audit.export-concurrency} (4) exports stream at once on a pod,
 *       each holding one pool connection and one thread of the MVC async executor ({@code MvcAsyncConfig});
 *       another is refused before it is recorded (503 {@code EXPORT_BUSY}, {@code Retry-After}). The export
 *       routes run outside open-in-view, so the request holds no connection while the body streams. A second
 *       export of the same organization waits at most {@code certping.audit.export-lock-timeout-ms} for the
 *       first one's lock (429 {@code EXPORT_IN_PROGRESS}).</li>
 *   <li><b>Truncation.</b> The status is sent before the rows, so an export that fails midway ends short:
 *       {@code X-Audit-Export-Rows} carries the rows counted when it was recorded, which a client compares with
 *       the rows it received; a JSON export cut short also lacks its closing {@code ]} and does not parse.</li>
 *   <li><b>Metrics.</b> {@code certping_audit_export_total{view,format,outcome}} (outcome
 *       {@code stream_failed}: recorded, then broke while streaming), {@code certping_audit_export_rows{view}} and {@code certping_audit_export_duration{view,outcome}}.</li>
 * </ul>
 */
@Slf4j
@Service
public class AuditTrailExporter {

    static final String EXPORT_METRIC = "certping.audit.export";
    static final String ROWS_METRIC = "certping.audit.export.rows";
    static final String DURATION_METRIC = "certping.audit.export.duration";

    /** How long the export's lock, count and row may take before it is refused. */
    private static final int GATE_TIMEOUT_SECONDS = 15;
    private static final Duration LIMIT_WINDOW = Duration.ofHours(1);
    private static final AuditReason TOO_LARGE = AuditReason.of(AuditExportRefusedException.TOO_LARGE);
    /** How long a refused export should wait: for a slot on this pod, or for the organization's lock. */
    static final long BUSY_RETRY_SECONDS = 10;
    static final long IN_PROGRESS_RETRY_SECONDS = 5;

    private final AuditTrailReader reader;
    private final AuditEventQueryStore queries;
    private final AuditEventStore events;
    private final AuditedReads staff;
    private final ObjectMapper json;
    private final Clock clock;
    private final TransactionTemplate gate;
    private final TransactionTemplate streaming;
    private final int maxRows;
    private final int exportsPerHour;
    private final Semaphore streams;

    public AuditTrailExporter(AuditTrailReader reader, AuditEventQueryStore queries, AuditEventStore events,
                              AuditedReads staff, ObjectMapper json, Clock clock,
                              PlatformTransactionManager transactionManager,
                              @Value("${certping.audit.export-max-rows:10000}") int maxRows,
                              @Value("${certping.audit.exports-per-hour:10}") int exportsPerHour,
                              @Value("${certping.audit.export-concurrency:4}") int concurrency) {
        if (maxRows < 1 || exportsPerHour < 1 || concurrency < 1) {
            throw new IllegalArgumentException(
                    "certping.audit.export-max-rows, exports-per-hour and export-concurrency must be positive");
        }
        this.streams = new Semaphore(concurrency);
        this.reader = reader;
        this.queries = queries;
        this.events = events;
        this.staff = staff;
        this.json = json;
        this.clock = clock;
        this.maxRows = maxRows;
        this.exportsPerHour = exportsPerHour;
        this.gate = new TransactionTemplate(transactionManager);
        this.gate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.gate.setTimeout(GATE_TIMEOUT_SECONDS);
        this.streaming = new TransactionTemplate(transactionManager);
        this.streaming.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.streaming.setReadOnly(true);
    }

    /**
     * An export ready to stream: its file name, its type, the body that writes it, and how many rows it holds
     * (counted when it was recorded; the {@code X-Audit-Export-Rows} header).
     */
    public record AuditExport(String fileName, MediaType contentType, StreamingResponseBody body, long rows) {

        /** The header carrying {@link #rows}, so a client can tell an export that ended short. */
        public static final String ROWS_HEADER = "X-Audit-Export-Rows";

        /** The {@code Content-Disposition} value: an attachment under {@link #fileName}. */
        public String contentDisposition() {
            return "attachment; filename=\"" + fileName + "\"";
        }
    }

    /** The formats an export is written in. */
    enum Format {
        CSV(new MediaType("text", "csv", StandardCharsets.UTF_8), "csv"),
        JSON(MediaType.APPLICATION_JSON, "json");

        final MediaType contentType;
        final String extension;

        Format(MediaType contentType, String extension) {
            this.contentType = contentType;
            this.extension = extension;
        }

        static Format of(String requested) {
            if (requested == null || requested.isBlank()) {
                return CSV;
            }
            try {
                return valueOf(requested.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException unknown) {
                throw new BadRequestException("Invalid format: want csv or json");
            }
        }
    }

    /** How a view is written: its file, the event recording it, its CSV layout and its JSON entries. */
    private record Layout<T>(AuditTrailView view, String file, AuditEventType recorded, List<String> header,
                             BiFunction<List<AuditEventRecord>, AuditVisibilityPolicy.Viewer, List<T>> render,
                             Function<T, List<String>> csvRow) {

        String metricView() {
            return view.name().toLowerCase(Locale.ROOT);
        }
    }

    // ── Customer exports ─────────────────────────────────────────────────

    /**
     * The customer list's rows matching {@code filter} (without the sensitive reads unless
     * {@code category=ACCESS}), recorded as {@code audit_log.exported}.
     */
    public AuditExport exportActivity(AuditEventFilterRequest filter, String format, boolean ascending,
                                      AuditVisibilityPolicy.Viewer viewer) {
        AuditEntryRenderer renderer = reader.renderer();
        return exportCustomer(new Layout<>(AuditTrailView.ACTIVITY, "audit-log", AuditEventType.AUDIT_LOG_EXPORTED,
                AuditCsv.ACTIVITY_HEADER, renderer::activity, AuditCsv::activityRow), filter, format, ascending, viewer);
    }

    /** The Access view's rows matching {@code filter}, recorded as {@code access_log.exported}. */
    public AuditExport exportAccess(AuditAccessFilterRequest filter, String format,
                                    AuditVisibilityPolicy.Viewer viewer) {
        AuditEntryRenderer renderer = reader.renderer();
        return exportCustomer(new Layout<>(AuditTrailView.ACCESS, "access-log", AuditEventType.ACCESS_LOG_EXPORTED,
                AuditCsv.ACCESS_HEADER, renderer::access, AuditCsv::accessRow), AuditTrailReader.accessFilter(filter),
                format, false, viewer);
    }

    private <T> AuditExport exportCustomer(Layout<T> layout, AuditEventFilterRequest filter, String requestedFormat,
                                           boolean ascending, AuditVisibilityPolicy.Viewer viewer) {
        Format format = Format.of(requestedFormat);
        refuseCursor(filter);
        Long organizationId = viewer.organizationId();
        if (organizationId == null) {
            throw new BadRequestException("Name the organization to export (organizationId), or export from the "
                    + "platform audit log");
        }
        AuditTrailReader.Resolved resolved = reader.resolve(layout.view(), filter, null, viewer, ascending, true);
        Permit permit = acquire(layout, format);
        try {
            return recordedThenStreamed(layout, format, resolved, organizationId, viewer, permit);
        } catch (RuntimeException refused) {
            permit.release();
            throw refused;
        }
    }

    private <T> AuditExport recordedThenStreamed(Layout<T> layout, Format format, AuditTrailReader.Resolved resolved,
                                                 long organizationId, AuditVisibilityPolicy.Viewer viewer,
                                                 Permit permit) {
        Instant now = clock.instant();
        AuditEventQuery query = fixedEnd(resolved.query(), now);
        AuditSubject.AuditSubjectBuilder subject = subject(query, format).organizationId(organizationId);
        long rows;
        try {
            rows = gate.execute(status -> {
                queries.lockExports(organizationId);
                AuditEventQueryStore.RecentExports recent = queries.exportsSince(organizationId, now.minus(LIMIT_WINDOW));
                if (recent.count() >= exportsPerHour) {
                    Instant freed = recent.oldest() == null ? now.plus(LIMIT_WINDOW) : recent.oldest().plus(LIMIT_WINDOW);
                    throw AuditExportRefusedException.limit(exportsPerHour,
                            Math.max(1, Duration.between(now, freed).toSeconds()));
                }
                long matching = queries.countForExport(query, maxRows + 1);
                AuditEventRow row = matching > maxRows
                        ? AuditEvents.failure(layout.recorded(), subject.build(), TOO_LARGE)
                        : AuditEvents.success(layout.recorded(), subject.count((int) matching).build());
                events.insert(row);
                return matching;
            });
        } catch (AuditExportRefusedException refused) {
            count(layout, format, "limited");
            throw refused;
        } catch (QueryTimeoutException timedOut) {
            count(layout, format, "timeout");
            throw timedOut;
        } catch (RuntimeException notRecorded) {
            if (SqlStates.isLockNotAvailable(notRecorded)) {
                // Another export of the organization holds the lock past export-lock-timeout-ms.
                count(layout, format, "in_progress");
                throw AuditExportRefusedException.inProgress(IN_PROGRESS_RETRY_SECONDS);
            }
            count(layout, format, "not_recorded");
            log.error("[AuditExport] the {} export of organization {} could not be recorded, so it was refused ({})",
                    layout.metricView(), organizationId, notRecorded.getClass().getSimpleName());
            throw AuditExportRefusedException.notRecorded();
        }
        if (rows > maxRows) {
            count(layout, format, "too_large");
            throw AuditExportRefusedException.tooLarge(maxRows);
        }
        return stream(layout, format, query, viewer, fileName(layout.file(), organizationId, now), rows, permit);
    }

    // ── Platform export ──────────────────────────────────────────────────

    /**
     * The platform view's rows matching {@code filter} (super admins only): of one organization or all, either
     * visibility, at most 90 days. Exporting an organization's trail writes {@code support.audit_log_exported}
     * into it, one row per export, before any row is read; every organization's, an internal row.
     */
    public AuditExport exportPlatform(AuditPlatformFilterRequest filter, String requestedFormat,
                                      AuditVisibilityPolicy.Viewer viewer) {
        AuditTrailReader.requireSuperAdmin(viewer);
        AuditEntryRenderer renderer = reader.renderer();
        Layout<com.certmanagement.dto.audit.AuditPlatformEntryDto> layout = new Layout<>(AuditTrailView.PLATFORM,
                "certping-audit-log", AuditEventType.SUPPORT_AUDIT_LOG_EXPORTED, AuditCsv.PLATFORM_HEADER,
                renderer::platform, AuditCsv::platformRow);
        Format format = Format.of(requestedFormat);
        refuseCursor(filter);
        AuditTrailReader.Resolved resolved = reader.resolve(AuditTrailView.PLATFORM, filter,
                AuditTrailReader.visibility(filter), viewer, false, false);
        Permit permit = acquire(layout, format);
        try {
            return supportExport(layout, format, resolved, viewer, permit);
        } catch (RuntimeException refused) {
            permit.release();
            throw refused;
        }
    }

    private AuditExport supportExport(Layout<com.certmanagement.dto.audit.AuditPlatformEntryDto> layout,
                                      Format format, AuditTrailReader.Resolved resolved,
                                      AuditVisibilityPolicy.Viewer viewer, Permit permit) {
        Instant now = clock.instant();
        AuditEventQuery query = fixedEnd(resolved.query(), now);
        long rows;
        try {
            rows = queries.countForExport(query, maxRows + 1);
        } catch (QueryTimeoutException timedOut) {
            count(layout, format, "timeout");
            throw timedOut;
        }
        if (rows > maxRows) {
            count(layout, format, "too_large");
            throw AuditExportRefusedException.tooLarge(maxRows);
        }
        if (!staff.staffExport(layout.recorded(), viewer.organizationId(), subject(query, format)
                .count((int) rows).build())) {
            count(layout, format, "not_recorded");
            throw AuditExportRefusedException.notRecorded();
        }
        return stream(layout, format, query, viewer, fileName(layout.file(), viewer.organizationId(), now), rows,
                permit);
    }

    // ── Streaming ────────────────────────────────────────────────────────

    /**
     * One of this pod's export slots, released once: by the body when it ends, by the export when it is refused,
     * and, should the body never run (its submission rejected, the request timed out first), by
     * {@link AuditExportSlotInterceptor} when the async request completes. Every call after the first does nothing.
     */
    public final class Permit {
        private final AtomicBoolean held = new AtomicBoolean(true);

        private Permit() {
        }

        public void release() {
            if (held.compareAndSet(true, false)) {
                streams.release();
            }
        }
    }

    /** The request attribute holding the export's {@link Permit}, for {@link AuditExportSlotInterceptor}. */
    public static final String PERMIT_ATTRIBUTE = AuditTrailExporter.class.getName() + ".PERMIT";

    /** Export slots free on this pod. */
    public int availableSlots() {
        return streams.availablePermits();
    }

    /**
     * A slot to stream an export in, or a 503 {@code EXPORT_BUSY} when this pod streams as many as it allows. The
     * slot is also kept on the request, so it is given back when the request completes whatever became of the body.
     */
    private Permit acquire(Layout<?> layout, Format format) {
        if (!streams.tryAcquire()) {
            count(layout, format, "busy");
            throw AuditExportRefusedException.busy(BUSY_RETRY_SECONDS);
        }
        Permit permit = new Permit();
        RequestAttributes request = RequestContextHolder.getRequestAttributes();
        if (request != null) {
            request.setAttribute(PERMIT_ATTRIBUTE, permit, RequestAttributes.SCOPE_REQUEST);
        }
        return permit;
    }

    private <T> AuditExport stream(Layout<T> layout, Format format, AuditEventQuery query,
                                   AuditVisibilityPolicy.Viewer viewer, String fileName, long rows, Permit permit) {
        count(layout, format, "started");
        if (viewer.organizationId() != null) {
            // Looked up on the request thread: the body runs on another.
            viewer.disabledFeatureKeys();
        }
        StreamingResponseBody body = output -> {
            Timer.Sample sample = Timer.start();
            Writer out = new BufferedWriter(new OutputStreamWriter(output, StandardCharsets.UTF_8));
            // Recorded already (a SUCCESS row that stays as written: the trail is append-only); a stream that breaks
            // now is logged and counted as stream_failed, and the client sees fewer rows than X-Audit-Export-Rows.
            String outcome = "stream_failed";
            try {
                long written = format == Format.CSV
                        ? writeCsv(layout, query, viewer, out)
                        : writeJson(layout, query, viewer, out);
                out.flush();
                outcome = "completed";
                DistributionSummary.builder(ROWS_METRIC).tag("view", layout.metricView()).register(Metrics.globalRegistry)
                        .record(written);
            } catch (UncheckedIOException failed) {
                stopped(layout, viewer, rows, failed.getCause());
                throw failed.getCause();
            } catch (RuntimeException | IOException failed) {
                stopped(layout, viewer, rows, failed);
                throw failed;
            } finally {
                permit.release();
                count(layout, format, outcome);
                sample.stop(Timer.builder(DURATION_METRIC).tag("view", layout.metricView()).tag("outcome", outcome)
                        .register(Metrics.globalRegistry));
            }
        };
        return new AuditExport(fileName + "." + format.extension, format.contentType, body, rows);
    }

    /**
     * The status and the first rows may be sent already: the export ends short. Its row in the trail says it was
     * made, with the rows counted; this line and {@code certping_audit_export_total{outcome="stream_failed"}} say
     * it did not complete.
     */
    private static void stopped(Layout<?> layout, AuditVisibilityPolicy.Viewer viewer, long rows, Exception failure) {
        log.error("[AuditExport] the {} export of organization {} ({} rows recorded) failed while streaming ({})",
                layout.metricView(), viewer.organizationId() == null ? "all" : viewer.organizationId(), rows,
                failure.getClass().getSimpleName());
    }

    private <T> long writeCsv(Layout<T> layout, AuditEventQuery query, AuditVisibilityPolicy.Viewer viewer, Writer out)
            throws IOException {
        AuditCsv.write(out, layout.header());
        return streamRows(query, chunk -> {
            for (T entry : layout.render().apply(chunk, viewer)) {
                AuditCsv.write(out, layout.csvRow().apply(entry));
            }
            out.flush();
        });
    }

    private <T> long writeJson(Layout<T> layout, AuditEventQuery query, AuditVisibilityPolicy.Viewer viewer,
                               Writer out) throws IOException {
        // The servlet's stream is closed by the container, not by the generator.
        JsonGenerator generator = json.createGenerator(out).configure(StreamWriteFeature.AUTO_CLOSE_TARGET, false);
        generator.writeStartArray();
        long written = streamRows(query, chunk -> {
            for (T entry : layout.render().apply(chunk, viewer)) {
                json.writeValue(generator, entry);
            }
            generator.flush();
        });
        generator.writeEndArray();
        generator.flush();
        return written;
    }

    /** A chunk's writer, which may fail on the response's stream. */
    @FunctionalInterface
    private interface ChunkWriter {
        void write(List<AuditEventRecord> chunk) throws IOException;
    }

    private long streamRows(AuditEventQuery query, ChunkWriter writer) {
        Long written = streaming.execute(status -> queries.stream(query, maxRows, chunk -> {
            try {
                writer.write(chunk);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }));
        return written == null ? 0 : written;
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static void refuseCursor(AuditEventFilterRequest filter) {
        if (filter.getCursor() != null && !filter.getCursor().isBlank()) {
            throw new BadRequestException("An export takes no cursor: it returns every matching entry");
        }
    }

    /** The window's end fixed at {@code now} when none was asked for, so the rows streamed are the rows counted. */
    private static AuditEventQuery fixedEnd(AuditEventQuery query, Instant now) {
        return query.to() == null ? query.toBuilder().to(now).build() : query;
    }

    private static AuditSubject.AuditSubjectBuilder subject(AuditEventQuery query, Format format) {
        Map<String, String> range = new java.util.LinkedHashMap<>();
        if (query.from() != null) {
            range.put("from", query.from().toString());
        }
        if (query.to() != null) {
            range.put("to", query.to().toString());
        }
        range.put("format", format.name());
        return AuditSubject.builder().format(format.name()).attributes(range);
    }

    /** {@code audit-log-acme-2026-10-10}: the view, the organization's name (else its id, else all) and the day. */
    private String fileName(String file, Long organizationId, Instant now) {
        String organization = "all-organizations";
        if (organizationId != null) {
            String name = queries.organizationNames(Set.of(organizationId)).get(organizationId);
            String slug = name == null ? "" : name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-")
                    .replaceAll("^-+|-+$", "");
            if (slug.length() > 40) {
                slug = slug.substring(0, 40).replaceAll("-+$", "");
            }
            organization = slug.isEmpty() ? "org-" + organizationId : slug;
        }
        return file + "-" + organization + "-" + LocalDate.ofInstant(now, ZoneOffset.UTC);
    }

    private static void count(Layout<?> layout, Format format, String outcome) {
        Metrics.counter(EXPORT_METRIC, "view", layout.metricView(), "format", format.extension, "outcome", outcome)
                .increment();
    }
}
