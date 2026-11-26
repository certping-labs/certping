// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Lookup;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DnsPropagationVerifier}.
 * <p>
 * The two dnsjava-facing seams ({@code nsHasRecord}, {@code lookupNameservers}) are
 * exposed as {@code protected} for exactly this reason — dnsjava's static-init resolver config
 * makes {@code Lookup} unreliable to mock. Tests here subclass the verifier and inject canned
 * outcomes to exercise the poll loop, unanimity semantics, and error paths without touching real DNS.
 */
class DnsPropagationVerifierTest {

    private AgentProperties properties;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getAcme().getDnsVerification().setMaxAttempts(3);
        properties.getAcme().getDnsVerification().setPollIntervalMs(1);
    }

    @Test
    void retryUnlessFinal_timeoutBeforeTheLastWait_isRetried() {
        PermanentAgentException timeout = new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "not visible");

        RuntimeException mapped = DnsPropagationVerifier.retryUnlessFinal(timeout, false);

        assertThat(mapped).isInstanceOfSatisfying(RetryableAgentException.class, e -> {
            assertThat(e.getErrorCode()).isEqualTo(DnsPropagationVerifier.PROPAGATION_PENDING);
            assertThat(e.getMessage()).contains("not visible");
            assertThat(e.getRetryAfter()).isNull();
        });
    }

    @Test
    void retryUnlessFinal_timeoutOnTheLastWait_staysPermanent() {
        PermanentAgentException timeout = new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "not visible");

        assertThat(DnsPropagationVerifier.retryUnlessFinal(timeout, true)).isSameAs(timeout);
    }

    @Test
    void retryUnlessFinal_otherFailure_isUnchanged() {
        PermanentAgentException other = new PermanentAgentException("DNS_NS_LOOKUP_FAILED", "no NS");

        assertThat(DnsPropagationVerifier.retryUnlessFinal(other, false)).isSameAs(other);
    }

    @Test
    void verifyAll_nullRecords_throws() {
        DnsPropagationVerifier verifier = new DnsPropagationVerifier(properties);
        assertThatThrownBy(() -> verifier.verifyAll(null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_VERIFICATION_EMPTY"));
    }

    @Test
    void verifyAll_emptyRecords_throws() {
        DnsPropagationVerifier verifier = new DnsPropagationVerifier(properties);
        assertThatThrownBy(() -> verifier.verifyAll(List.of()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_VERIFICATION_EMPTY"));
    }

    @Test
    void verifyAll_noAuthoritativeNs_throwsDnsNsLookupFailed() {
        DnsPropagationVerifier verifier = new TestableVerifier(properties, List.of(), Map.of());
        assertThatThrownBy(() -> verifier.verifyAll(
                List.of(new DnsPropagationVerifier.TxtRecord("_acme-challenge.example.com", "v"))))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_NS_LOOKUP_FAILED"));
    }

    @Test
    void verifyAll_recordVisibleOnSecondCheck_rechecksAfterOneSecondNotTheFullInterval() {
        properties.getAcme().getDnsVerification().setMaxAttempts(3);
        properties.getAcme().getDnsVerification().setPollIntervalMs(5000);
        List<String> ns = List.of("ns1.example.net");
        TestableVerifier verifier = new TestableVerifier(properties, ns,
                Map.of("ns1.example.net", List.of(false, true)));

        long started = System.nanoTime();
        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord("_acme-challenge.example.com", "v")));
        long elapsedMs = (System.nanoTime() - started) / 1_000_000;

        assertThat(verifier.nsQueryCount.get("ns1.example.net")).isEqualTo(2);
        assertThat(elapsedMs).isBetween(DnsPropagationVerifier.INITIAL_RECHECK_MS - 50, 3000L);
    }

    @Test
    void verifyAll_allNsAgree_succeedsOnFirstAttempt() {
        List<String> ns = List.of("ns51.domaincontrol.com", "ns52.domaincontrol.com");
        Map<String, List<Boolean>> schedule = Map.of(
                "ns51.domaincontrol.com", List.of(true),
                "ns52.domaincontrol.com", List.of(true));
        TestableVerifier verifier = new TestableVerifier(properties, ns, schedule);

        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.example.com", "v5RzaLilv…")));

        assertThat(verifier.nsQueryCount.get("ns51.domaincontrol.com")).isEqualTo(1);
        assertThat(verifier.nsQueryCount.get("ns52.domaincontrol.com")).isEqualTo(1);
    }

    @Test
    void verifyAll_oneNsLagsThenCatchesUp_succeeds() {
        List<String> ns = List.of("ns51.domaincontrol.com", "ns52.domaincontrol.com");
        // ns51 has it from t=0; ns52 lags one poll.
        Map<String, List<Boolean>> schedule = Map.of(
                "ns51.domaincontrol.com", List.of(true, true),
                "ns52.domaincontrol.com", List.of(false, true));
        TestableVerifier verifier = new TestableVerifier(properties, ns, schedule);

        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.example.com", "v")));

        // Second poll saw both agree — the previous "any-NS-wins" bug would have declared verified
        // after only one poll. That the poll loop ran twice is the assertion that unanimity matters.
        assertThat(verifier.nsQueryCount.get("ns52.domaincontrol.com")).isEqualTo(2);
    }

    @Test
    void verifyAll_oneNsPermanentlyLags_timesOut() {
        List<String> ns = List.of("ns51.domaincontrol.com", "ns52.domaincontrol.com");
        Map<String, List<Boolean>> schedule = Map.of(
                "ns51.domaincontrol.com", List.of(true, true, true),
                "ns52.domaincontrol.com", List.of(false, false, false));
        TestableVerifier verifier = new TestableVerifier(properties, ns, schedule);

        assertThatThrownBy(() -> verifier.verifyAll(
                List.of(new DnsPropagationVerifier.TxtRecord("_acme-challenge.example.com", "v"))))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROPAGATION_TIMEOUT"));
        assertThat(verifier.nsQueryCount.get("ns52.domaincontrol.com")).isEqualTo(3);
    }

    @Test
    void verifyAll_singleNs_behavesLikeUnanimous() {
        List<String> ns = List.of("ns.solo.test");
        Map<String, List<Boolean>> schedule = Map.of("ns.solo.test", List.of(true));
        TestableVerifier verifier = new TestableVerifier(properties, ns, schedule);

        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.solo.test", "v")));

        assertThat(verifier.nsQueryCount.get("ns.solo.test")).isEqualTo(1);
    }

    @Test
    void verifyAll_findsTheZoneByWalkingUpFromTheRecordName() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.example.co.uk"),
                Map.of("ns1.example.co.uk", List.of(true))).zoneAt("example.co.uk");

        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.www.example.co.uk", "v")));

        assertThat(verifier.nsResolveCalls).containsExactly(
                "_acme-challenge.www.example.co.uk", "www.example.co.uk", "example.co.uk");
        assertThat(verifier.nsQueryCount.get("ns1.example.co.uk")).isEqualTo(1);
    }

    @Test
    void verifyAll_aDelegatedChallengeNameIsItsOwnZone() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.acme-dns.test"),
                Map.of("ns1.acme-dns.test", List.of(true))).zoneAt("_acme-challenge.example.com");

        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord("_acme-challenge.example.com.", "v")));

        assertThat(verifier.nsResolveCalls).containsExactly("_acme-challenge.example.com");
    }

    @Test
    void verifyAll_noZoneUpToTheTopLevel_failsWithoutAskingTheRoot() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns"), Map.of()).zoneAt("elsewhere.test");

        assertThatThrownBy(() -> verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.a.example.com", "v"))))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_NS_LOOKUP_FAILED"));
        assertThat(verifier.nsResolveCalls).containsExactly(
                "_acme-challenge.a.example.com", "a.example.com", "example.com");
    }

    @Test
    void awaitAll_usesTheAutomatedBudgetAndLeavesALateRecordToTheNextAttempt() {
        properties.getAcme().getAutomatedDnsVerification().setMaxAttempts(5);
        properties.getAcme().getAutomatedDnsVerification().setPollIntervalMs(1);
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.slow.test"),
                Map.of("ns1.slow.test", List.of(false)));

        assertThatThrownBy(() -> verifier.awaitAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.slow.test", "v")), false))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(DnsPropagationVerifier.PROPAGATION_PENDING);
                    assertThat(e.getMessage()).contains("after 5 attempts");
                });
        assertThat(verifier.nsQueryCount.get("ns1.slow.test")).isEqualTo(5);
    }

    @Test
    void awaitAll_finalWait_failsAsATimeoutInsteadOfRetrying() {
        properties.getAcme().getAutomatedDnsVerification().setMaxAttempts(2);
        properties.getAcme().getAutomatedDnsVerification().setPollIntervalMs(1);
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.slow.test"),
                Map.of("ns1.slow.test", List.of(false)));

        assertThatThrownBy(() -> verifier.awaitAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.slow.test", "v")), true))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_TIMEOUT"));
    }

    @Test
    void verifyAll_aCnameToAnotherZoneIsNotTheZoneOfTheName() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.example.com"),
                Map.of("ns1.example.com", List.of(true))).zoneAt("example.com")
                .answering("www.example.com", new DnsPropagationVerifier.NsAnswer(Lookup.SUCCESSFUL,
                        List.of(new DnsPropagationVerifier.NsRecord("other.net", "ns1.other.net"))));

        verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord("_acme-challenge.www.example.com", "v")));

        assertThat(verifier.nsResolveCalls).containsExactly(
                "_acme-challenge.www.example.com", "www.example.com", "example.com");
        assertThat(verifier.nsQueryCount).containsOnlyKeys("ns1.example.com");
    }

    @Test
    void verifyAll_aFailingResolverStopsTheWalkAsATransientError() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.example.com"), Map.of())
                .zoneAt("example.com")
                .answering("www.example.com", new DnsPropagationVerifier.NsAnswer(Lookup.TRY_AGAIN, List.of()));

        assertThatThrownBy(() -> verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.www.example.com", "v"))))
                .isInstanceOfSatisfying(TransientAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_NS_LOOKUP_UNAVAILABLE"));
        assertThat(verifier.nsResolveCalls).doesNotContain("example.com");
    }

    @Test
    void verifyAll_anUnrecoverableResolverErrorIsTransientToo() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns"), Map.of())
                .answering("_acme-challenge.example.com",
                        new DnsPropagationVerifier.NsAnswer(Lookup.UNRECOVERABLE, List.of()));

        assertThatThrownBy(() -> verifier.verifyAll(List.of(new DnsPropagationVerifier.TxtRecord(
                "_acme-challenge.example.com", "v"))))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void awaitAll_recordVisibleWithinTheBudget_succeeds() {
        properties.getAcme().getAutomatedDnsVerification().setMaxAttempts(5);
        properties.getAcme().getAutomatedDnsVerification().setPollIntervalMs(1);
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.slow.test"),
                Map.of("ns1.slow.test", List.of(false, false, false, true)));

        verifier.awaitAll(List.of(new DnsPropagationVerifier.TxtRecord("_acme-challenge.slow.test", "v")), false);

        assertThat(verifier.nsQueryCount.get("ns1.slow.test")).isEqualTo(4);
    }

    @Test
    void verifyRecords_cname_isCheckedAsACnameOnEveryNameserverOfItsDomain() {
        List<String> ns = List.of("ns1.example.net", "ns2.example.net");
        TestableVerifier verifier = new TestableVerifier(properties, ns, Map.of(
                "ns1.example.net", List.of(true), "ns2.example.net", List.of(true)));

        verifier.verifyRecords(List.of(new DnsPropagationVerifier.ExpectedRecord(
                DnsRecordType.CNAME, "_0a1b.shop.example.com", "aa.bb.dcv.example")));

        assertThat(verifier.cnameQueries).containsExactly(
                "ns1.example.net _0a1b.shop.example.com. aa.bb.dcv.example",
                "ns2.example.net _0a1b.shop.example.com. aa.bb.dcv.example");
        assertThat(verifier.nsResolveCalls).containsExactly("_0a1b.shop.example.com");
    }

    @Test
    void verifyRecords_cnameMissingOnOneNameserver_timesOutNamingTheType() {
        TestableVerifier verifier = new TestableVerifier(properties, List.of("ns1.example.net", "ns2.example.net"),
                Map.of("ns1.example.net", List.of(true), "ns2.example.net", List.of(false)));

        assertThatThrownBy(() -> verifier.verifyRecords(List.of(new DnsPropagationVerifier.ExpectedRecord(
                DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example"))))
                .isInstanceOfSatisfying(PermanentAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_TIMEOUT");
                    assertThat(e.getMessage()).contains("CNAME record '_0a1b.example.com'");
                });
    }

    /**
     * Test double that skips the real dnsjava calls. Overrides the two protected seams:
     *   - {@code lookupNameservers} → answers the canned NS list at the zone apex, or a set answer
     *   - {@code nsHasRecord} → returns the next scheduled boolean per NS
     * Records call counts and NS-resolve arguments so tests can assert behavior.
     */
    private static final class TestableVerifier extends DnsPropagationVerifier {
        private final List<String> nameservers;
        private final Map<String, List<Boolean>> schedule;
        private final Map<String, AtomicInteger> pollIndex = new HashMap<>();
        final Map<String, Integer> nsQueryCount = new HashMap<>();
        final List<String> nsResolveCalls = new ArrayList<>();
        final List<String> cnameQueries = new ArrayList<>();
        private String zoneApex;
        private final Map<String, NsAnswer> answers = new HashMap<>();

        TestableVerifier(AgentProperties properties, List<String> nameservers,
                         Map<String, List<Boolean>> schedule) {
            super(properties);
            this.nameservers = nameservers;
            this.schedule = schedule;
            schedule.keySet().forEach(ns -> pollIndex.put(ns, new AtomicInteger(0)));
        }

        /** Answers nameservers for {@code apex} only, as a recursive resolver does for one zone. */
        TestableVerifier zoneAt(String apex) {
            this.zoneApex = apex;
            return this;
        }

        /** Answers {@code answer} for {@code name}, in place of the zone-apex rule. */
        TestableVerifier answering(String name, NsAnswer answer) {
            answers.put(name, answer);
            return this;
        }

        @Override
        protected NsAnswer lookupNameservers(String name) {
            nsResolveCalls.add(name);
            if (answers.containsKey(name)) {
                return answers.get(name);
            }
            return zoneApex == null || zoneApex.equals(name)
                    ? new NsAnswer(Lookup.SUCCESSFUL, nameservers.stream().map(ns -> new NsRecord(name, ns)).toList())
                    : new NsAnswer(Lookup.TYPE_NOT_FOUND, List.of());
        }

        @Override
        protected boolean nsHasCname(String ns, String absoluteName, String expectedTarget, String logName) {
            cnameQueries.add(ns + " " + absoluteName + " " + expectedTarget);
            return nsHasRecord(ns, absoluteName, expectedTarget, logName);
        }

        @Override
        protected boolean nsHasRecord(String ns, String absoluteName, String expectedValue, String logName) {
            nsQueryCount.merge(ns, 1, Integer::sum);
            List<Boolean> outcomes = schedule.get(ns);
            if (outcomes == null || outcomes.isEmpty()) {
                return false;
            }
            int idx = pollIndex.get(ns).getAndIncrement();
            return outcomes.get(Math.min(idx, outcomes.size() - 1));
        }
    }
}
