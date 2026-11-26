// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Tests Cloudflare DNS provider HTTP behaviour (addTxtRecord / deleteTxtRecord)
 * using a mock RestTemplate injected via ReflectionTestUtils.
 */
@ExtendWith(MockitoExtension.class)
class CloudflareDnsProviderHttpTest {

    @Mock private RestTemplate restTemplate;

    private CloudflareDnsProvider provider;

    @BeforeEach
    void setUp() {
        provider = new CloudflareDnsProvider("valid-api-token");
        ReflectionTestUtils.setField(provider, "restTemplate", restTemplate);
    }

    // ── addTxtRecord ──────────────────────────────────────────────────────────

    @Test
    void addTxtRecord_success_returnsRecordId() {
        givenZoneIdLookupReturns("zone-abc");

        ObjectNode resultNode = JsonNodeFactory.instance.objectNode();
        resultNode.put("id", "record-xyz");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", true);
        addBody.set("result", resultNode);

        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(addBody));

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest-val");

        assertThat(recordId).isEqualTo("record-xyz");
    }

    @Test
    void addTxtRecord_withAZoneId_writesThereWithoutLookingUpZones() {
        CloudflareDnsProvider pinned = new CloudflareDnsProvider("dns-edit-only-token", "zone-pinned");
        ReflectionTestUtils.setField(pinned, "restTemplate", restTemplate);
        ObjectNode resultNode = JsonNodeFactory.instance.objectNode();
        resultNode.put("id", "record-1");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", true);
        addBody.set("result", resultNode);
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones/zone-pinned/dns_records"),
                eq(HttpMethod.POST), any(), eq(JsonNode.class))).thenReturn(ResponseEntity.ok(addBody));

        assertThat(pinned.addTxtRecord("_acme-challenge.example.com", "digest-val")).isEqualTo("record-1");
        verify(restTemplate, never()).exchange(contains("/zones?name="), any(HttpMethod.class), any(), eq(JsonNode.class));
    }

    @Test
    void addTxtRecord_nonSuccessResponse_lookupExistingRecord() {
        givenZoneIdLookupReturns("zone-abc");

        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", false);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(addBody));

        // findExistingRecord call returns nothing
        ObjectNode emptyResult = JsonNodeFactory.instance.objectNode();
        emptyResult.put("success", false);
        when(restTemplate.exchange(contains("/dns_records?name="), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(emptyResult));

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest-val");

        assertThat(recordId).startsWith("existing-");
    }

    @Test
    void addTxtRecord_authError_throwsPermanentException() {
        givenZoneIdLookupReturns("zone-abc");

        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "Unauthorized", null, null, null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    void addTxtRecord_duplicateRecord_returnsExistingMarker() {
        givenZoneIdLookupReturns("zone-abc");

        HttpClientErrorException duplicate = HttpClientErrorException.create(
                HttpStatus.BAD_REQUEST, "Bad Request",
                null, "An identical record already exists".getBytes(), null);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(duplicate);

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "val");

        assertThat(recordId).startsWith("existing-");
    }

    @Test
    void addTxtRecord_rateLimited_throwsRetryable() {
        // HTTP 429 from Cloudflare is now classified as a rate-limit and routed through
        // RetryableAgentException so the listener re-enqueues with a scheduled delay instead
        // of the immediate redelivery the old TransientAgentException path produced.
        givenZoneIdLookupReturns("zone-abc");

        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests", null, null, null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"));
    }

    // ── getZoneId ─────────────────────────────────────────────────────────────

    @Test
    void addTxtRecord_zoneNotFound_throwsPermanentException() {
        ObjectNode emptyZone = JsonNodeFactory.instance.objectNode();
        emptyZone.put("success", true);
        emptyZone.set("result", JsonNodeFactory.instance.arrayNode());
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(emptyZone));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_ZONE_NOT_FOUND"));
    }

    @Test
    void addTxtRecord_zoneAuthError_throwsPermanentException() {
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN, "Forbidden", null, null, null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── deleteTxtRecord ───────────────────────────────────────────────────────

    @Test
    void deleteTxtRecord_success_callsDeleteEndpoint() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records/record-xyz"), eq(HttpMethod.DELETE), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));

        provider.deleteTxtRecord("_acme-challenge.example.com", "record-xyz");

        verify(restTemplate).exchange(contains("/dns_records/record-xyz"), eq(HttpMethod.DELETE), any(), eq(JsonNode.class));
    }

    @Test
    void deleteTxtRecord_notFound_doesNotThrow() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records/"), eq(HttpMethod.DELETE), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.NOT_FOUND, "Not Found", null, null, null));

        // Should not throw — 404 means record is already gone
        provider.deleteTxtRecord("_acme-challenge.example.com", "record-xyz");
    }

    @Test
    void deleteTxtRecord_nonFatalHttpError_doesNotThrow() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records/"), eq(HttpMethod.DELETE), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.INTERNAL_SERVER_ERROR, "Error", null, null, null));

        // Should not throw — delete is best-effort
        provider.deleteTxtRecord("_acme-challenge.example.com", "record-xyz");
    }

    @Test
    void addTxtRecord_genericHttpError_throwsTransientException() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(
                        HttpStatus.BAD_REQUEST, "Bad Request", null, "some other error".getBytes(), null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    void addTxtRecord_nonSuccessResponse_returnsExistingFromLookup() {
        givenZoneIdLookupReturns("zone-abc");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", false);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(addBody));

        // findExistingRecord returns a valid id
        ObjectNode otherChallenge = JsonNodeFactory.instance.objectNode();
        otherChallenge.put("id", "other-record-id");
        otherChallenge.put("content", "other-digest");
        ObjectNode existingEntry = JsonNodeFactory.instance.objectNode();
        existingEntry.put("id", "existing-record-id");
        existingEntry.put("content", "digest");
        ObjectNode lookupBody = JsonNodeFactory.instance.objectNode();
        lookupBody.put("success", true);
        lookupBody.set("result", JsonNodeFactory.instance.arrayNode().add(otherChallenge).add(existingEntry));
        when(restTemplate.exchange(contains("/dns_records?name="), eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(lookupBody));

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest");
        assertThat(recordId).isEqualTo("existing-record-id");
    }

    @Test
    void addTxtRecord_identicalRecord_isLookedUpByItsContentSoCleanupDeletesIt() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad Request", null,
                        "An identical record already exists".getBytes(), null));
        ObjectNode existingEntry = JsonNodeFactory.instance.objectNode();
        existingEntry.put("id", "record-77");
        existingEntry.put("content", "val");
        ObjectNode lookupBody = JsonNodeFactory.instance.objectNode();
        lookupBody.put("success", true);
        lookupBody.set("result", JsonNodeFactory.instance.arrayNode().add(existingEntry));
        when(restTemplate.exchange(contains("/dns_records?name="), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(lookupBody));

        assertThat(provider.addTxtRecord("_acme-challenge.example.com", "val")).isEqualTo("record-77");
    }

    @Test
    void addTxtRecord_findsTheZoneByWalkingUpFromTheName() {
        ObjectNode none = JsonNodeFactory.instance.objectNode();
        none.put("success", true);
        none.set("result", JsonNodeFactory.instance.arrayNode());
        ObjectNode zone = JsonNodeFactory.instance.objectNode();
        zone.put("id", "zone-uk");
        zone.put("status", "active");
        ObjectNode found = JsonNodeFactory.instance.objectNode();
        found.put("success", true);
        found.set("result", JsonNodeFactory.instance.arrayNode().add(zone));
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones?name=www.example.co.uk"),
                eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(none));
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones?name=example.co.uk"),
                eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(found));
        ObjectNode created = JsonNodeFactory.instance.objectNode();
        created.put("success", true);
        created.set("result", JsonNodeFactory.instance.objectNode().put("id", "record-uk"));
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones/zone-uk/dns_records"),
                eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(created));

        assertThat(provider.addTxtRecord("_acme-challenge.www.example.co.uk", "val")).isEqualTo("record-uk");
        verify(restTemplate, never()).exchange(eq("https://api.cloudflare.com/client/v4/zones?name=co.uk"),
                eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class));
    }

    @Test
    void addTxtRecord_noZoneUpToTheTopLevel_isZoneNotFoundWithoutAskingTheTld() {
        ObjectNode none = JsonNodeFactory.instance.objectNode();
        none.put("success", true);
        none.set("result", JsonNodeFactory.instance.arrayNode());
        when(restTemplate.exchange(contains("/zones?name="), eq(HttpMethod.GET), any(),
                eq(tools.jackson.databind.JsonNode.class))).thenReturn(ResponseEntity.ok(none));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.a.example.com", "val"))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_ZONE_NOT_FOUND"));
        verify(restTemplate, times(2)).exchange(contains("/zones?name="), eq(HttpMethod.GET), any(),
                eq(tools.jackson.databind.JsonNode.class));
    }

    @Test
    void addTxtRecord_aZoneThatIsNotActiveIsSkippedForItsParent() {
        ObjectNode pending = JsonNodeFactory.instance.objectNode();
        pending.put("id", "zone-pending");
        pending.put("status", "pending");
        ObjectNode pendingBody = JsonNodeFactory.instance.objectNode();
        pendingBody.put("success", true);
        pendingBody.set("result", JsonNodeFactory.instance.arrayNode().add(pending));
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones?name=shop.example.com"),
                eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(pendingBody));
        ObjectNode active = JsonNodeFactory.instance.objectNode();
        active.put("id", "zone-active");
        active.put("status", "active");
        ObjectNode activeBody = JsonNodeFactory.instance.objectNode();
        activeBody.put("success", true);
        activeBody.set("result", JsonNodeFactory.instance.arrayNode().add(active));
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones?name=example.com"),
                eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(activeBody));
        ObjectNode created = JsonNodeFactory.instance.objectNode();
        created.put("success", true);
        created.set("result", JsonNodeFactory.instance.objectNode().put("id", "record-1"));
        when(restTemplate.exchange(eq("https://api.cloudflare.com/client/v4/zones/zone-active/dns_records"),
                eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(created));

        assertThat(provider.addTxtRecord("_acme-challenge.shop.example.com", "val")).isEqualTo("record-1");
    }

    @Test
    void addTxtRecord_identicalRecordWithQuotedContent_isStillFound() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad Request", null,
                        "An identical record already exists".getBytes(), null));
        ObjectNode existingEntry = JsonNodeFactory.instance.objectNode();
        existingEntry.put("id", "record-q");
        existingEntry.put("content", "\"val\"");
        ObjectNode lookupBody = JsonNodeFactory.instance.objectNode();
        lookupBody.put("success", true);
        lookupBody.set("result", JsonNodeFactory.instance.arrayNode().add(existingEntry));
        when(restTemplate.exchange(contains("/dns_records?name="), eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenReturn(ResponseEntity.ok(lookupBody));

        assertThat(provider.addTxtRecord("_acme-challenge.example.com", "val")).isEqualTo("record-q");
    }

    @Test
    void addTxtRecord_zoneLookupBadGateway_isTransientNotAFailedCertificate() {
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenThrow(HttpServerErrorException.create(HttpStatus.BAD_GATEWAY, "Bad Gateway", null, null, null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOfSatisfying(TransientAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    void addTxtRecord_apiUnreachable_isTransient() {
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenThrow(new ResourceAccessException("connect timed out"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void deleteTxtRecord_serverError_isNotFatal() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records/record-1"), eq(HttpMethod.DELETE), any(), eq(tools.jackson.databind.JsonNode.class)))
                .thenThrow(HttpServerErrorException.create(HttpStatus.BAD_GATEWAY, "Bad Gateway", null, null, null));

        provider.deleteTxtRecord("_acme-challenge.example.com", "record-1");
    }

    @Test
    void addTxtRecord_nonSuccess_findExistingThrows_returnsFallbackMarker() {
        givenZoneIdLookupReturns("zone-abc");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", false);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(addBody));
        // findExistingRecord throws — caught and returns null, so we get "existing-" marker
        when(restTemplate.exchange(contains("/dns_records?name="), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenThrow(new RuntimeException("boom"));

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest");
        assertThat(recordId).startsWith("existing-");
    }

    @Test
    void addTxtRecord_zoneLookupRateLimited_throwsRetryable() {
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests", null, null, null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void addTxtRecord_zoneLookupGenericHttpError_throwsTransient() {
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad Request", null, null, null));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void addTxtRecord_zoneLookupNonSuccessBody_throwsZoneNotFound() {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("success", false);
        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(body));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_ZONE_NOT_FOUND"));
    }

    @Test
    void deleteTxtRecord_existingMarker_skipsHttpCall() {
        provider.deleteTxtRecord("_acme-challenge.example.com", "existing-_acme-challenge.example.com");

        verifyNoInteractions(restTemplate);
    }

    @Test
    void deleteTxtRecord_rateLimited_throwsRetryable() {
        givenZoneIdLookupReturns("zone-abc");
        when(restTemplate.exchange(contains("/dns_records/"), eq(HttpMethod.DELETE), any(), eq(JsonNode.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests", null, null, null));

        assertThatThrownBy(() -> provider.deleteTxtRecord("_acme-challenge.example.com", "record-xyz"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void addTxtRecord_wildcardDomain_stripsAndSucceeds() {
        givenZoneIdLookupReturns("zone-abc");
        ObjectNode resultNode = JsonNodeFactory.instance.objectNode();
        resultNode.put("id", "rec-1");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", true);
        addBody.set("result", resultNode);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(addBody));

        // wildcard record without _acme-challenge prefix exercises the other strip branch
        assertThat(provider.addTxtRecord("*.example.com", "digest")).isEqualTo("rec-1");
    }

    @Test
    void addTxtRecord_singleLabelName_isNeverLookedUpAsAZone() {
        assertThatThrownBy(() -> provider.addTxtRecord("localhost", "digest"))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_ZONE_NOT_FOUND"));
        verifyNoInteractions(restTemplate);
    }

    // ── helper ────────────────────────────────────────────────────────────────

    private void givenZoneIdLookupReturns(String zoneId) {
        ObjectNode zoneResult = JsonNodeFactory.instance.objectNode();
        zoneResult.put("id", zoneId);
        zoneResult.put("name", "example.com");
        zoneResult.put("status", "active");

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("success", true);
        body.set("result", JsonNodeFactory.instance.arrayNode().add(zoneResult));

        when(restTemplate.exchange(contains("/zones"), eq(HttpMethod.GET), any(), eq(JsonNode.class)))
                .thenReturn(ResponseEntity.ok(body));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addRecord_cname_isCreatedUnproxied() {
        givenZoneIdLookupReturns("zone-abc");
        ObjectNode resultNode = JsonNodeFactory.instance.objectNode();
        resultNode.put("id", "record-cname");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", true);
        addBody.set("result", resultNode);
        ArgumentCaptor<HttpEntity<Map<String, Object>>> request =
                ArgumentCaptor.forClass(HttpEntity.class);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), request.capture(),
                eq(JsonNode.class))).thenReturn(ResponseEntity.ok(addBody));

        String recordId = provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example");

        assertThat(recordId).isEqualTo("record-cname");
        assertThat(request.getValue().getBody())
                .containsEntry("type", "CNAME")
                .containsEntry("name", "_0a1b.example.com")
                .containsEntry("content", "aa.bb.dcv.example")
                .containsEntry("proxied", false);
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_bodyCarriesNoProxiedFlag() {
        givenZoneIdLookupReturns("zone-abc");
        ObjectNode addBody = JsonNodeFactory.instance.objectNode();
        addBody.put("success", true);
        addBody.set("result", JsonNodeFactory.instance.objectNode().put("id", "r"));
        ArgumentCaptor<HttpEntity<Map<String, Object>>> request =
                ArgumentCaptor.forClass(HttpEntity.class);
        when(restTemplate.exchange(contains("/dns_records"), eq(HttpMethod.POST), request.capture(),
                eq(JsonNode.class))).thenReturn(ResponseEntity.ok(addBody));

        provider.addTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(request.getValue().getBody()).containsEntry("type", "TXT").doesNotContainKey("proxied");
    }
}
