// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Shared TXT workflow used by CA integrations:
 * - add TXT records (provider selected per authorization domain)
 * - wait for propagation on authoritative nameservers
 *
 * Cleanup is intentionally returned to the caller so it can decide when it is safe to remove TXT records
 * (e.g. after cert is persisted). When the workflow itself fails, it removes the records it added, except
 * where the caller resumes the same challenge and the records are only still propagating.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DnsTxtWorkflowService {

    private final DnsProviderSelector dnsProviderSelector;
    private final DnsPropagationVerifier dnsPropagationVerifier;
    private final DnsTxtCleanupService dnsTxtCleanupService;

    public record TxtRecordRequest(String authorizationDomain, String recordName, String recordValue) {}

    public record TxtWorkflowResult(
        List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries,
        List<DnsPropagationVerifier.TxtRecord> propagationChecks
    ) {}

    /**
     * Adds the records and waits for them. Any failure removes the records added, because the next attempt
     * starts a new challenge with new values.
     *
     * @param finalWait this attempt's wait is the last one allowed
     * @throws RetryableAgentException {@code DNS_PROPAGATION_PENDING} when they are not everywhere in time
     * @throws PermanentAgentException {@code DNS_PROPAGATION_TIMEOUT} when not, and {@code finalWait}
     */
    public TxtWorkflowResult addTxtRecordsAndWaitForPropagation(
        List<TxtRecordRequest> requests,
        String rootDomain,
        DnsProvider rootDnsProvider,
        Map<String, DnsProvider> sanDnsProviders,
        boolean finalWait
    ) {
        return addAndAwait(requests, rootDomain, rootDnsProvider, sanDnsProviders, finalWait, false);
    }

    /**
     * As {@link #addTxtRecordsAndWaitForPropagation}, for a challenge the next attempt publishes again
     * unchanged (a resumed ACME order): records still propagating when the wait runs out stay, so that
     * attempt finds them further along, unless this was the last wait allowed.
     */
    public TxtWorkflowResult addTxtRecordsForResumableChallenge(
        List<TxtRecordRequest> requests,
        String rootDomain,
        DnsProvider rootDnsProvider,
        Map<String, DnsProvider> sanDnsProviders,
        boolean finalWait
    ) {
        return addAndAwait(requests, rootDomain, rootDnsProvider, sanDnsProviders, finalWait, true);
    }

    private TxtWorkflowResult addAndAwait(List<TxtRecordRequest> requests, String rootDomain,
                                          DnsProvider rootDnsProvider, Map<String, DnsProvider> sanDnsProviders,
                                          boolean finalWait, boolean keepWhilePropagating) {
        if (requests == null || requests.isEmpty()) {
            throw new PermanentAgentException("DNS_TXT_REQUESTS_EMPTY", "No TXT record requests provided");
        }
        requests.forEach(DnsTxtWorkflowService::requireComplete);

        List<DnsTxtCleanupService.DnsTxtCleanupEntry> cleanupEntries = new ArrayList<>();
        List<DnsPropagationVerifier.TxtRecord> toVerify = new ArrayList<>();
        try {
            for (TxtRecordRequest req : requests) {
                DnsProvider dns = dnsProviderSelector.selectProvider(
                    req.authorizationDomain(), rootDomain, rootDnsProvider, sanDnsProviders);
                log.info("Adding DNS TXT record: {} = {} via {}",
                    req.recordName(), req.recordValue(), dns.getClass().getSimpleName());
                String recordId = dns.addTxtRecord(req.recordName(), req.recordValue());
                cleanupEntries.add(new DnsTxtCleanupService.DnsTxtCleanupEntry(dns, req.recordName(), recordId));
                toVerify.add(new DnsPropagationVerifier.TxtRecord(req.recordName(), req.recordValue()));
            }
            dnsPropagationVerifier.awaitAll(toVerify, finalWait);
        } catch (RuntimeException e) {
            if (!(keepWhilePropagating && isStillPropagating(e))) {
                dnsTxtCleanupService.cleanup(cleanupEntries);
            }
            throw e;
        }
        return new TxtWorkflowResult(cleanupEntries, toVerify);
    }

    private static boolean isStillPropagating(RuntimeException e) {
        return e instanceof RetryableAgentException retryable
                && DnsPropagationVerifier.PROPAGATION_PENDING.equals(retryable.getErrorCode());
    }

    private static void requireComplete(TxtRecordRequest req) {
        if (req == null
            || req.authorizationDomain() == null || req.authorizationDomain().isBlank()
            || req.recordName() == null || req.recordName().isBlank()
            || req.recordValue() == null || req.recordValue().isBlank()) {
            throw new PermanentAgentException("DNS_TXT_REQUEST_INVALID",
                    "TXT record request is missing required fields");
        }
    }
}
