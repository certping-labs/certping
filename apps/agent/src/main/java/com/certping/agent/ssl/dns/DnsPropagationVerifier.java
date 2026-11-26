// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.util.MdcContextPropagator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

/**
 * Verifies domain-validation records on authoritative nameservers before the CA is asked to check them: ACME
 * DNS-01 TXT records before {@code challenge.trigger()}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DnsPropagationVerifier {

    /** The error code of a wait for the agent's own records that ran out of budget; retried, not failed. */
    public static final String PROPAGATION_PENDING = "DNS_PROPAGATION_PENDING";

    /** The error code of a wait that ran out of budget and is not retried. */
    public static final String PROPAGATION_TIMEOUT = "DNS_PROPAGATION_TIMEOUT";

    /** First re-check after a miss; later ones double up to the configured poll interval. */
    static final long INITIAL_RECHECK_MS = 1000;

    private final AgentProperties properties;

    public record TxtRecord(String recordName, String expectedValue) {}

    /** A record expected on every authoritative nameserver: TXT content, or a CNAME target without a trailing dot. */
    public record ExpectedRecord(DnsRecordType type, String recordName, String expectedValue) {}

    /**
     * Verify all TXT records in parallel. Blocks until all pass or any fails.
     *
     * @throws PermanentAgentException {@code DNS_PROPAGATION_TIMEOUT} or {@code DNS_NS_LOOKUP_FAILED}
     */
    public void verifyAll(List<TxtRecord> records) {
        if (records == null || records.isEmpty()) {
            throw new PermanentAgentException("DNS_VERIFICATION_EMPTY",
                    "No TXT records to verify for DNS propagation check");
        }
        verifyRecords(toExpected(records));
    }

    /**
     * As {@link #verifyAll}, for records of any type.
     *
     * @throws PermanentAgentException {@code DNS_PROPAGATION_TIMEOUT} or {@code DNS_NS_LOOKUP_FAILED}
     */
    public void verifyRecords(List<ExpectedRecord> records) {
        verify(records, properties.getAcme().getDnsVerification(),
                message -> new PermanentAgentException(PROPAGATION_TIMEOUT, message));
    }

    /**
     * Waits for TXT records the agent published itself, within the longer automated budget
     * ({@code acme.automated-dns-verification}). Records that are still not everywhere by then are left
     * to the next attempt rather than failed, unless this is the last wait allowed: a DNS provider's edge servers
     * and secondaries can lag by minutes.
     *
     * @param finalWait this is the last wait the records get
     * @throws RetryableAgentException {@code DNS_PROPAGATION_PENDING} when the budget runs out
     * @throws PermanentAgentException {@code DNS_PROPAGATION_TIMEOUT} when it runs out on the final wait, or
     *                                 {@code DNS_NS_LOOKUP_FAILED}
     */
    public void awaitAll(List<TxtRecord> records, boolean finalWait) {
        verify(toExpected(records), properties.getAcme().getAutomatedDnsVerification(), finalWait
                ? message -> new PermanentAgentException(PROPAGATION_TIMEOUT, message)
                : message -> new RetryableAgentException(PROPAGATION_PENDING, message));
    }

    /**
     * {@code e} as {@code DNS_PROPAGATION_PENDING} when it is a {@code DNS_PROPAGATION_TIMEOUT} and this is not the
     * last wait allowed, else {@code e} unchanged. For waits with no retry of their own ({@link #verifyRecords} and
     * {@link #verifyAll}, as a manual validation uses): slow propagation is
     * often temporary, and {@code agent.retry.max-retries-by-reason} bounds the retries.
     */
    public static RuntimeException retryUnlessFinal(RuntimeException e, boolean finalWait) {
        if (finalWait || !(e instanceof PermanentAgentException permanent)
                || !PROPAGATION_TIMEOUT.equals(permanent.getErrorCode())) {
            return e;
        }
        return new RetryableAgentException(PROPAGATION_PENDING, e.getMessage(), null, e);
    }

    private void verify(List<ExpectedRecord> records, AgentProperties.DnsVerificationProperties cfg,
                        Function<String, AgentException> onTimeout) {
        if (records == null || records.isEmpty()) {
            throw new PermanentAgentException("DNS_VERIFICATION_EMPTY",
                    "No records to verify for DNS propagation check");
        }

        // Wrap each task with MdcContextPropagator so the worker thread inherits the caller's MDC
        // (requestId / correlationId / messageId) — without this, logs emitted inside verifySingle
        // would lose the trace prefix and break end-to-end correlation.
        List<CompletableFuture<Void>> futures = records.stream()
                .map(r -> CompletableFuture.runAsync(MdcContextPropagator.wrap(() -> verifySingle(r, cfg, onTimeout))))
                .toList();

        try {
            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
        } catch (CompletionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof AgentException agentException) {
                throw agentException;
            }
            throw new PermanentAgentException(PROPAGATION_TIMEOUT,
                    "DNS propagation check failed: " + cause.getMessage(), cause);
        }
    }

    private void verifySingle(ExpectedRecord record, AgentProperties.DnsVerificationProperties cfg,
                              Function<String, AgentException> onTimeout) {
        List<String> nameservers = zoneNameservers(record.recordName());
        if (nameservers.isEmpty()) {
            throw new PermanentAgentException("DNS_NS_LOOKUP_FAILED",
                    "Could not resolve the authoritative nameservers of the zone holding: " + record.recordName());
        }

        // The budget is the same as maxAttempts checks pollIntervalMs apart, but the first re-checks
        // come sooner (1 s, doubling up to pollIntervalMs): authoritative servers usually serve a new
        // record within a second or two, and a full interval per job caps the agent's throughput.
        long interval = Math.max(0, cfg.getPollIntervalMs());
        long budget = interval * Math.max(0, cfg.getMaxAttempts() - 1L);
        long waited = 0;
        long nextSleep = Math.min(interval, INITIAL_RECHECK_MS);
        for (int attempt = 1; ; attempt++) {
            if (isRecordVisible(record, nameservers)) {
                log.info("[DnsPropagation] Record verified: {} (attempt {}, waited {} ms)",
                        record.recordName(), attempt, waited);
                return;
            }
            if (waited >= budget || cfg.getMaxAttempts() <= 1) {
                break;
            }
            long sleep = Math.min(nextSleep, budget - waited);
            log.info("[DnsPropagation] Record not visible yet: {} (attempt {}, next check in {} ms)",
                    record.recordName(), attempt, sleep);
            try {
                Thread.sleep(sleep);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TransientAgentException("ACME_INTERRUPTED",
                        "DNS propagation wait interrupted: " + e.getMessage(), e);
            }
            waited += sleep;
            nextSleep = Math.min(interval, Math.max(1, nextSleep * 2));
        }

        throw onTimeout.apply(record.type() + " record '" + record.recordName()
                + "' not visible in authoritative DNS after " + cfg.getMaxAttempts() + " attempts × "
                + cfg.getPollIntervalMs() + "ms. Ensure the record is added correctly and DNS has propagated.");
    }

    /**
     * The nameservers of the closest zone holding {@code recordName}: those of the name itself when it is
     * a zone cut (a delegated challenge name), else of each parent in turn. Two labels are not always a
     * zone: {@code example.co.uk}'s nameservers are not {@code co.uk}'s. Only NS records owned by the name
     * asked count: a CNAME there leads the resolver to another zone, whose nameservers do not serve this
     * name. The walk moves up only on "no such name" or "no NS here"; a failing resolver stops it.
     *
     * @throws TransientAgentException {@code DNS_NS_LOOKUP_UNAVAILABLE} when the resolver fails
     */
    private List<String> zoneNameservers(String recordName) {
        String name = withoutTrailingDot(recordName.trim().toLowerCase(Locale.ROOT));
        while (name.indexOf('.') > 0) {
            NsAnswer answer = lookupNameservers(name);
            switch (answer.result()) {
                case Lookup.SUCCESSFUL -> {
                    List<String> nameservers = answer.ownedBy(name);
                    if (!nameservers.isEmpty()) {
                        return nameservers;
                    }
                }
                case Lookup.HOST_NOT_FOUND, Lookup.TYPE_NOT_FOUND -> { }
                default -> throw new TransientAgentException("DNS_NS_LOOKUP_UNAVAILABLE",
                        "The resolver could not look up the nameservers of " + name + " (result "
                                + answer.result() + ")");
            }
            name = name.substring(name.indexOf('.') + 1);
        }
        return List.of();
    }

    // Require the expected record to be visible on EVERY authoritative NS before declaring propagated.
    // LE picks a random authoritative NS to validate against; if any replica lags, the challenge
    // fails with INVALID even though other replicas already serve the record.
    private boolean isRecordVisible(ExpectedRecord record, List<String> nameservers) {
        String recordName = record.recordName();
        String absolute = recordName.endsWith(".") ? recordName : recordName + ".";
        for (String ns : nameservers) {
            boolean served = record.type() == DnsRecordType.CNAME
                    ? nsHasCname(ns, absolute, record.expectedValue(), recordName)
                    : nsHasRecord(ns, absolute, record.expectedValue(), recordName);
            if (!served) {
                log.info("[DnsPropagation] NS {} does not yet have expected {} for {}", ns, record.type(), recordName);
                return false;
            }
        }
        return !nameservers.isEmpty();
    }

    /**
     * As {@link #nsHasRecord}, for a CNAME whose target equals {@code expectedTarget}, ignoring case and the
     * trailing dot.
     */
    protected boolean nsHasCname(String ns, String absoluteName, String expectedTarget, String logName) {
        String expected = withoutTrailingDot(expectedTarget);
        for (InetAddress addr : addressesOf(ns)) {
            try {
                for (Record rec : query(addr, absoluteName, Type.CNAME)) {
                    if (rec instanceof CNAMERecord cname
                            && expected.equalsIgnoreCase(withoutTrailingDot(cname.getTarget().toString()))) {
                        return true;
                    }
                }
            } catch (TextParseException e) {
                log.warn("[DnsPropagation] Invalid CNAME lookup name {}: {}", logName, e.getMessage());
            } catch (Exception e) {
                log.warn("[DnsPropagation] NS query error for {} via {}: {}",
                        ns, addr.getHostAddress(), e.getMessage());
            }
        }
        return false;
    }

    private static InetAddress[] addressesOf(String ns) {
        try {
            return InetAddress.getAllByName(ns);
        } catch (Exception e) {
            log.warn("[DnsPropagation] NS host resolution failed for {}: {}", ns, e.getMessage());
            return new InetAddress[0];
        }
    }

    private static Record[] query(InetAddress addr, String absoluteName, int type) throws Exception {
        SimpleResolver resolver = new SimpleResolver(addr.getHostAddress());
        resolver.setTCP(true);
        Lookup lookup = new Lookup(absoluteName, type);
        lookup.setResolver(resolver);
        lookup.setCache(null);
        Record[] recs = lookup.run();
        return lookup.getResult() == Lookup.SUCCESSFUL && recs != null ? recs : new Record[0];
    }

    private static String withoutTrailingDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }

    // A NS "has the record" when ANY of its resolved IPs serves the expected TXT. Do NOT require
    // every IP path — getAllByName returns both A and AAAA, and if the pod is IPv4-only the AAAA
    // query silently fails and we'd wrongly report the NS as lagging forever.
    // Protected so unit tests can override with a deterministic answer (dnsjava's Lookup is not
    // reliably mockable across platforms).
    protected boolean nsHasRecord(String ns, String absoluteName, String expectedValue, String logName) {
        for (InetAddress addr : addressesOf(ns)) {
            try {
                for (Record rec : query(addr, absoluteName, Type.TXT)) {
                    if (rec instanceof TXTRecord txt) {
                        for (String s : txt.getStrings()) {
                            if (expectedValue.equals(s)) {
                                return true;
                            }
                        }
                    }
                }
            } catch (TextParseException e) {
                log.warn("[DnsPropagation] Invalid TXT lookup name {}: {}", logName, e.getMessage());
            } catch (Exception e) {
                log.warn("[DnsPropagation] NS query error for {} via {}: {}",
                        ns, addr.getHostAddress(), e.getMessage());
            }
        }
        return false;
    }

    /** A {@link Lookup} result code and the NS records it returned, each with the name that owns it. */
    protected record NsAnswer(int result, List<NsRecord> records) {

        List<String> ownedBy(String name) {
            return records.stream().filter(record -> record.owner().equalsIgnoreCase(name))
                    .map(NsRecord::target).toList();
        }
    }

    /** One NS record: its owner name and the nameserver it names, both without the trailing dot. */
    protected record NsRecord(String owner, String target) {}

    // Protected so unit tests can supply canned answers (dnsjava's Lookup is not reliably mockable).
    protected NsAnswer lookupNameservers(String name) {
        try {
            Lookup lookup = new Lookup(name, Type.NS);
            Record[] recs = lookup.run();
            List<NsRecord> records = recs == null ? List.of() : Arrays.stream(recs)
                    .filter(NSRecord.class::isInstance)
                    .map(NSRecord.class::cast)
                    .map(ns -> new NsRecord(withoutTrailingDot(ns.getName().toString()),
                            withoutTrailingDot(ns.getTarget().toString())))
                    .toList();
            return new NsAnswer(lookup.getResult(), records);
        } catch (TextParseException e) {
            log.warn("[DnsPropagation] Invalid NS lookup name {}: {}", name, e.getMessage());
            return new NsAnswer(Lookup.HOST_NOT_FOUND, List.of());
        }
    }

    private static List<ExpectedRecord> toExpected(List<TxtRecord> records) {
        return records == null ? List.of() : records.stream()
                .map(r -> new ExpectedRecord(DnsRecordType.TXT, r.recordName(), r.expectedValue()))
                .toList();
    }
}
