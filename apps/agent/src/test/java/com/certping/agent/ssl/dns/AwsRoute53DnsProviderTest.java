// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.*;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AwsRoute53DnsProviderTest {

    @Mock private Route53Client mockRoute53;

    private AwsRoute53DnsProvider provider;

    @BeforeEach
    void setUp() {
        // Provide placeholder creds — no real AWS calls; Route53Client is injected via reflection
        provider = new AwsRoute53DnsProvider("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG");
        ReflectionTestUtils.setField(provider, "route53", mockRoute53);
        lenient().when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenReturn(ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of()).build());
    }

    // ── constructor validation ─────────────────────────────────────────────────

    @Test
    void constructor_blankAccessKeyId_throwsPermanentException() {
        assertThatThrownBy(() -> new AwsRoute53DnsProvider("", "secretKey"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void constructor_blankSecretKey_throwsPermanentException() {
        assertThatThrownBy(() -> new AwsRoute53DnsProvider("accessKey", "   "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── addTxtRecord ──────────────────────────────────────────────────────────

    @Test
    void addTxtRecord_success_returnsTheValueAsItsId() {
        givenHostedZoneFound("Z1234567890");
        ChangeResourceRecordSetsResponse changeResp = ChangeResourceRecordSetsResponse.builder()
                .changeInfo(ChangeInfo.builder().id("/change/C1234567890").status(ChangeStatus.PENDING).build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(changeResp);

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest-value");

        assertThat(recordId).isEqualTo("digest-value");
    }

    @Test
    void addTxtRecord_existingValueAtTheName_upsertsBothValues() {
        givenHostedZoneFound("Z1");
        givenTxtSet("_acme-challenge.example.com.", 300L, "\"apex-digest\"");
        givenChangeAccepted();

        provider.addTxtRecord("_acme-challenge.example.com", "wildcard-digest");

        ResourceRecordSet written = onlyChange(ChangeAction.UPSERT);
        assertThat(written.ttl()).isEqualTo(300L);
        assertThat(written.resourceRecords()).extracting(ResourceRecord::value)
                .containsExactly("\"apex-digest\"", "\"wildcard-digest\"");
    }

    @Test
    void addTxtRecord_valueAlreadyThere_isNotWrittenTwice() {
        givenHostedZoneFound("Z1");
        givenTxtSet("_acme-challenge.example.com.", 60L, "\"digest\"");
        givenChangeAccepted();

        provider.addTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(onlyChange(ChangeAction.UPSERT).resourceRecords()).extracting(ResourceRecord::value)
                .containsExactly("\"digest\"");
    }

    @Test
    void addTxtRecord_setOfALongerName_isNotMerged() {
        givenHostedZoneFound("Z1");
        givenTxtSet("_acme-challenge.example.com.au.", 60L, "\"other\"");
        givenChangeAccepted();

        provider.addTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(onlyChange(ChangeAction.UPSERT).resourceRecords()).extracting(ResourceRecord::value)
                .containsExactly("\"digest\"");
    }

    @Test
    void deleteTxtRecord_otherValueAtTheName_keepsIt() {
        givenHostedZoneFound("Z1");
        givenTxtSet("_acme-challenge.example.com.", 60L, "\"apex-digest\"", "\"wildcard-digest\"");
        givenChangeAccepted();

        provider.deleteTxtRecord("_acme-challenge.example.com", "apex-digest");

        assertThat(onlyChange(ChangeAction.UPSERT).resourceRecords()).extracting(ResourceRecord::value)
                .containsExactly("\"wildcard-digest\"");
    }

    @Test
    void deleteTxtRecord_lastValue_deletesTheSet() {
        givenHostedZoneFound("Z1");
        givenTxtSet("_acme-challenge.example.com.", 60L, "\"digest\"");
        givenChangeAccepted();

        provider.deleteTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(onlyChange(ChangeAction.DELETE).resourceRecords()).extracting(ResourceRecord::value)
                .containsExactly("\"digest\"");
    }

    @Test
    void deleteTxtRecord_valueNotThere_changesNothing() {
        givenHostedZoneFound("Z1");
        givenTxtSet("_acme-challenge.example.com.", 60L, "\"someone-else\"");

        provider.deleteTxtRecord("_acme-challenge.example.com", "digest");

        verify(mockRoute53, never()).changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class));
    }

    private void givenTxtSet(String name, long ttl, String... values) {
        ResourceRecordSet set = ResourceRecordSet.builder()
                .name(name)
                .type(RRType.TXT)
                .ttl(ttl)
                .resourceRecords(java.util.Arrays.stream(values)
                        .map(value -> ResourceRecord.builder().value(value).build()).toList())
                .build();
        when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenReturn(ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of(set)).build());
    }

    private void givenChangeAccepted() {
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(ChangeResourceRecordSetsResponse.builder()
                        .changeInfo(ChangeInfo.builder().id("/change/X").status(ChangeStatus.PENDING).build())
                        .build());
    }

    private ResourceRecordSet onlyChange(ChangeAction action) {
        ArgumentCaptor<ChangeResourceRecordSetsRequest> request =
                ArgumentCaptor.forClass(ChangeResourceRecordSetsRequest.class);
        verify(mockRoute53).changeResourceRecordSets(request.capture());
        Change change = request.getValue().changeBatch().changes().get(0);
        assertThat(change.action()).isEqualTo(action);
        return change.resourceRecordSet();
    }

    @Test
    void addTxtRecord_zoneNotFound_throwsPermanentException() {
        when(mockRoute53.listHostedZonesByName(any(ListHostedZonesByNameRequest.class)))
                .thenReturn(ListHostedZonesByNameResponse.builder().hostedZones(List.of()).build());

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_ZONE_NOT_FOUND"));
    }

    @Test
    void addTxtRecord_accessDenied_throwsPermanentException() {
        givenHostedZoneFound("Z1234567890");
        Route53Exception denied = (Route53Exception) Route53Exception.builder()
                .message("Access denied")
                .statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("AccessDenied")
                        .errorMessage("Access denied")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(denied);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    void addTxtRecord_transientRoute53Error_throwsRetryable() {
        // 503 ServiceUnavailable used to map to TransientAgentException("DNS_PROVIDER_ERROR")
        // which the listener abandon()ed for near-immediate redelivery. With the rate-limit
        // overhaul, RateLimitClassifier.fromAws() classifies 503 as throttle-shape (alongside
        // 429) and produces RetryableAgentException("DNS_PROVIDER_THROTTLED") so the listener
        // re-enqueues through the gateway with a scheduled delay instead of hammering the worker.
        givenHostedZoneFound("Z1234567890");
        Route53Exception transientEx = (Route53Exception) Route53Exception.builder()
                .message("Service unavailable")
                .statusCode(503)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ServiceUnavailable")
                        .errorMessage("503")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(transientEx);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"));
    }

    // ── deleteTxtRecord ───────────────────────────────────────────────────────

    @Test
    void deleteTxtRecord_success_deletesRecord() {
        givenHostedZoneFound("Z1234567890");
        ResourceRecordSet rrs = ResourceRecordSet.builder()
                .name("_acme-challenge.example.com")
                .type(RRType.TXT)
                .ttl(60L)
                .resourceRecords(ResourceRecord.builder().value("\"digest\"").build())
                .build();
        when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenReturn(ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of(rrs)).build());
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(ChangeResourceRecordSetsResponse.builder()
                        .changeInfo(ChangeInfo.builder().id("/change/DEL").status(ChangeStatus.PENDING).build())
                        .build());

        provider.deleteTxtRecord("_acme-challenge.example.com", "digest");

        verify(mockRoute53).changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class));
    }

    @Test
    void deleteTxtRecord_recordAlreadyGone_skipsDeletion() {
        givenHostedZoneFound("Z1234567890");
        when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenReturn(ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of()).build());

        provider.deleteTxtRecord("_acme-challenge.example.com", "/change/C123");

        verify(mockRoute53, never()).changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class));
    }

    @Test
    void deleteTxtRecord_route53Error_doesNotThrow() {
        givenHostedZoneFound("Z1234567890");
        when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenThrow(Route53Exception.builder()
                        .message("Error")
                        .statusCode(500)
                        .awsErrorDetails(AwsErrorDetails.builder().errorCode("InternalFailure").errorMessage("err").build())
                        .build());

        // Should not throw — deletion is best-effort
        provider.deleteTxtRecord("_acme-challenge.example.com", "/change/C123");
    }

    // ── helper ────────────────────────────────────────────────────────────────

    private void givenHostedZoneFound(String zoneId) {
        HostedZone zone = HostedZone.builder().id("/hostedzone/" + zoneId).name("example.com.").build();
        when(mockRoute53.listHostedZonesByName(any(ListHostedZonesByNameRequest.class)))
                .thenReturn(ListHostedZonesByNameResponse.builder().hostedZones(List.of(zone)).build());
    }

    @Test
    void addTxtRecord_route53Throttling_throwsRetryable() {
        // "Throttling" errorCode → AWS_THROTTLE_ERROR_CODES contains it → classified as throttle
        givenHostedZoneFound("Z1");
        Route53Exception throttle = (Route53Exception) Route53Exception.builder()
                .message("Rate exceeded")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .errorMessage("rate exceeded")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(throttle);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"));
    }

    @Test
    void addTxtRecord_priorRequestNotComplete_throwsRetryable() {
        givenHostedZoneFound("Z1");
        Route53Exception throttle = (Route53Exception) Route53Exception.builder()
                .message("Prior request not complete")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("PriorRequestNotComplete")
                        .errorMessage("...")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(throttle);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void addTxtRecord_unauthorizedStatus401_throwsAuthFailed() {
        givenHostedZoneFound("Z1");
        Route53Exception ex = (Route53Exception) Route53Exception.builder()
                .message("unauthorized")
                .statusCode(401)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("UnknownError")
                        .errorMessage("...")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(ex);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    void addTxtRecord_genericRoute53Error_throwsTransient() {
        givenHostedZoneFound("Z1");
        Route53Exception ex = (Route53Exception) Route53Exception.builder()
                .message("internal")
                .statusCode(500)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("InternalFailure")
                        .errorMessage("...")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(ex);

        // 500 is not classified as throttle by fromAws (only 429/503 are HTTP-coded throttles),
        // and not a throttle code, so we fall through to the generic transient path
        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    void deleteTxtRecord_throttledOnChangeRequest_throwsRetryable() {
        givenHostedZoneFound("Z1");
        ResourceRecordSet rrs = ResourceRecordSet.builder()
                .name("_acme-challenge.example.com")
                .type(RRType.TXT)
                .ttl(60L)
                .resourceRecords(ResourceRecord.builder().value("\"d\"").build())
                .build();
        when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenReturn(ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of(rrs)).build());
        Route53Exception throttle = (Route53Exception) Route53Exception.builder()
                .message("throttled")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .errorMessage("...")
                        .build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenThrow(throttle);

        assertThatThrownBy(() -> provider.deleteTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void addTxtRecord_wildcardRecord_stripsAndSucceeds() {
        givenHostedZoneFound("Z1");
        ChangeResourceRecordSetsResponse changeResp = ChangeResourceRecordSetsResponse.builder()
                .changeInfo(ChangeInfo.builder().id("/change/W").status(ChangeStatus.PENDING).build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(changeResp);

        // wildcard without _acme-challenge prefix → strip "*." path is covered
        assertThat(provider.addTxtRecord("*.example.com", "d")).isEqualTo("d");
    }

    @Test
    void addTxtRecord_singleLabelRecord_succeeds() {
        givenHostedZoneFound("Z1");
        ChangeResourceRecordSetsResponse changeResp = ChangeResourceRecordSetsResponse.builder()
                .changeInfo(ChangeInfo.builder().id("/change/S").status(ChangeStatus.PENDING).build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(changeResp);

        // single-label exercises parts.length<2 branch in getRegistrableDomain
        assertThat(provider.addTxtRecord("localhost", "d")).isEqualTo("d");
    }

    @Test
    void addTxtRecord_zoneIdWithoutPrefix_handled() {
        // HostedZone id without "/hostedzone/" prefix exercises the else-branch
        HostedZone zone = HostedZone.builder().id("Z-RAW-ID").name("example.com.").build();
        when(mockRoute53.listHostedZonesByName(any(ListHostedZonesByNameRequest.class)))
                .thenReturn(ListHostedZonesByNameResponse.builder().hostedZones(List.of(zone)).build());
        ChangeResourceRecordSetsResponse changeResp = ChangeResourceRecordSetsResponse.builder()
                .changeInfo(ChangeInfo.builder().id("/change/R").status(ChangeStatus.PENDING).build())
                .build();
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(changeResp);

        assertThat(provider.addTxtRecord("_acme-challenge.example.com", "d")).isEqualTo("d");
    }

    @Test
    void addRecord_cname_writesTheTargetFullyQualifiedAndUnquoted() {
        givenHostedZoneFound("Z1");
        when(mockRoute53.changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class)))
                .thenReturn(ChangeResourceRecordSetsResponse.builder()
                        .changeInfo(ChangeInfo.builder().id("/change/C1").status(ChangeStatus.PENDING).build())
                        .build());

        provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example");

        ArgumentCaptor<ChangeResourceRecordSetsRequest> request =
                ArgumentCaptor.forClass(ChangeResourceRecordSetsRequest.class);
        verify(mockRoute53).changeResourceRecordSets(request.capture());
        ResourceRecordSet rrs = request.getValue().changeBatch().changes().get(0).resourceRecordSet();
        assertThat(rrs.type()).isEqualTo(RRType.CNAME);
        assertThat(rrs.resourceRecords()).extracting(ResourceRecord::value).containsExactly("aa.bb.dcv.example.");
    }

    @Test
    void deleteRecord_cname_leavesARecordSetOfAnotherTypeAlone() {
        givenHostedZoneFound("Z1");
        ResourceRecordSet txt = ResourceRecordSet.builder()
                .name("_0a1b.example.com.")
                .type(RRType.TXT)
                .ttl(60L)
                .resourceRecords(ResourceRecord.builder().value("\"x\"").build())
                .build();
        when(mockRoute53.listResourceRecordSets(any(ListResourceRecordSetsRequest.class)))
                .thenReturn(ListResourceRecordSetsResponse.builder().resourceRecordSets(List.of(txt)).build());

        provider.deleteRecord(DnsRecordType.CNAME, "_0a1b.example.com", "/change/C1");

        verify(mockRoute53, never()).changeResourceRecordSets(any(ChangeResourceRecordSetsRequest.class));
    }
}
