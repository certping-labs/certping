// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DnsTxtWorkflowServiceTest {

    private static final String APEX = "_acme-challenge.example.com";
    private static final String API = "_acme-challenge.api.example.com";

    private final DnsProvider provider = mock(DnsProvider.class);
    private final DnsPropagationVerifier verifier = mock(DnsPropagationVerifier.class);
    private final DnsTxtWorkflowService workflow =
            new DnsTxtWorkflowService(new DnsProviderSelector(), verifier, new DnsTxtCleanupService());

    @Test
    void addsEveryRecordThenAwaitsThemWithTheAutomatedBudget() {
        when(provider.addTxtRecord(APEX, "v1")).thenReturn("rec-1");
        when(provider.addTxtRecord(API, "v2")).thenReturn("rec-2");

        DnsTxtWorkflowService.TxtWorkflowResult result = workflow.addTxtRecordsAndWaitForPropagation(
                twoRequests(), "example.com", provider, Map.of(), false);

        assertThat(result.cleanupEntries()).extracting(DnsTxtCleanupService.DnsTxtCleanupEntry::recordId)
                .containsExactly("rec-1", "rec-2");
        assertThat(result.propagationChecks()).hasSize(2);
        verify(verifier).awaitAll(anyList(), eq(false));
        verify(verifier, never()).verifyAll(anyList());
    }

    @Test
    void aFailedAddRemovesTheRecordsAlreadyAdded() {
        when(provider.addTxtRecord(APEX, "v1")).thenReturn("rec-1");
        when(provider.addTxtRecord(API, "v2")).thenThrow(new TransientAgentException("DNS_PROVIDER_ERROR", "down"));

        assertThatThrownBy(() -> workflow.addTxtRecordsAndWaitForPropagation(
                twoRequests(), "example.com", provider, Map.of(), false))
                .isInstanceOf(TransientAgentException.class);

        verify(provider).deleteTxtRecord(APEX, "rec-1");
    }

    @Test
    void recordsStillPropagatingStayForAResumableChallenge() {
        when(provider.addTxtRecord(APEX, "v1")).thenReturn("rec-1");
        when(provider.addTxtRecord(API, "v2")).thenReturn("rec-2");
        doThrow(pending()).when(verifier).awaitAll(anyList(), anyBoolean());

        assertThatThrownBy(() -> workflow.addTxtRecordsForResumableChallenge(
                twoRequests(), "example.com", provider, Map.of(), false))
                .isInstanceOf(RetryableAgentException.class);

        verify(provider, never()).deleteTxtRecord(APEX, "rec-1");
        verify(provider, never()).deleteTxtRecord(API, "rec-2");
    }

    @Test
    void recordsStillPropagatingAreRemovedWhenTheNextAttemptStartsANewChallenge() {
        when(provider.addTxtRecord(APEX, "v1")).thenReturn("rec-1");
        when(provider.addTxtRecord(API, "v2")).thenReturn("rec-2");
        doThrow(pending()).when(verifier).awaitAll(anyList(), anyBoolean());

        assertThatThrownBy(() -> workflow.addTxtRecordsAndWaitForPropagation(
                twoRequests(), "example.com", provider, Map.of(), false))
                .isInstanceOf(RetryableAgentException.class);

        verify(provider).deleteTxtRecord(APEX, "rec-1");
        verify(provider).deleteTxtRecord(API, "rec-2");
    }

    @Test
    void onTheFinalWaitTheRecordsOfAResumableChallengeAreRemoved() {
        when(provider.addTxtRecord(APEX, "v1")).thenReturn("rec-1");
        when(provider.addTxtRecord(API, "v2")).thenReturn("rec-2");
        doThrow(new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "not everywhere"))
                .when(verifier).awaitAll(anyList(), eq(true));

        assertThatThrownBy(() -> workflow.addTxtRecordsForResumableChallenge(
                twoRequests(), "example.com", provider, Map.of(), true))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_TIMEOUT"));

        verify(provider).deleteTxtRecord(APEX, "rec-1");
        verify(provider).deleteTxtRecord(API, "rec-2");
    }

    @Test
    void aPermanentWaitFailureRemovesTheRecordsEvenForAResumableChallenge() {
        when(provider.addTxtRecord(APEX, "v1")).thenReturn("rec-1");
        doThrow(new PermanentAgentException("DNS_NS_LOOKUP_FAILED", "no zone")).when(verifier).awaitAll(anyList(),
                anyBoolean());

        assertThatThrownBy(() -> workflow.addTxtRecordsForResumableChallenge(
                List.of(request("example.com", APEX, "v1")), "example.com", provider, Map.of(), false))
                .isInstanceOf(PermanentAgentException.class);

        verify(provider).deleteTxtRecord(APEX, "rec-1");
    }

    @Test
    void anIncompleteRequestIsRefusedBeforeAnyRecordIsAdded() {
        List<DnsTxtWorkflowService.TxtRecordRequest> requests = new ArrayList<>();
        requests.add(request("example.com", APEX, "v1"));
        requests.add(request("api.example.com", API, " "));

        assertThatThrownBy(() -> workflow.addTxtRecordsAndWaitForPropagation(
                requests, "example.com", provider, Map.of(), false))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_TXT_REQUEST_INVALID"));
        verify(provider, never()).addTxtRecord(APEX, "v1");
    }

    @Test
    void aNullRequestIsInvalid() {
        List<DnsTxtWorkflowService.TxtRecordRequest> requests = new ArrayList<>();
        requests.add(null);

        assertThatThrownBy(() -> workflow.addTxtRecordsAndWaitForPropagation(
                requests, "example.com", provider, Map.of(), false))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_TXT_REQUEST_INVALID"));
    }

    @Test
    void noRequestsAreRefused() {
        assertThatThrownBy(() -> workflow.addTxtRecordsAndWaitForPropagation(null, "example.com", provider, Map.of(), false))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_TXT_REQUESTS_EMPTY"));
        assertThatThrownBy(() -> workflow.addTxtRecordsAndWaitForPropagation(
                List.of(), "example.com", provider, Map.of(), false))
                .isInstanceOf(PermanentAgentException.class);
    }

    private static List<DnsTxtWorkflowService.TxtRecordRequest> twoRequests() {
        return List.of(request("example.com", APEX, "v1"), request("api.example.com", API, "v2"));
    }

    private static DnsTxtWorkflowService.TxtRecordRequest request(String domain, String name, String value) {
        return new DnsTxtWorkflowService.TxtRecordRequest(domain, name, value);
    }

    private static RetryableAgentException pending() {
        return new RetryableAgentException(DnsPropagationVerifier.PROPAGATION_PENDING, "not everywhere yet");
    }
}
