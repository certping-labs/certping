// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.certping.agent.ssl.dns.HttpRequestBodies.bodyOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

class CertPingDnsProviderTest {

    private static final String API_URL = "https://dns.example.test/api/v1/domains/token-api";
    private static final String RECORDS = API_URL + "/dns/zones/example.com/records";

    private final List<HttpRequest> sent = new ArrayList<>();
    private CertPingDnsProvider provider;

    @BeforeEach
    void setUp() {
        provider = new CertPingDnsProvider("cpk_live_key", API_URL);
    }

    @Test
    void constructor_blankApiKey_throwsCredentialInvalid() {
        assertThatThrownBy(() -> new CertPingDnsProvider(" ", API_URL))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void constructor_blankApiUrl_usesTokenApiDefault() {
        assertThat(ReflectionTestUtils.getField(new CertPingDnsProvider("k", null), "apiUrl"))
                .isEqualTo("https://dns-api.certping.com/api/v1/domains/token-api");
        assertThat(ReflectionTestUtils.getField(new CertPingDnsProvider("k", API_URL + "/"), "apiUrl"))
                .isEqualTo(API_URL);
    }

    @Test
    void addTxtRecord_postsTheChallengeWithBearerAndReturnsZoneScopedId() throws Exception {
        respond(req -> reply(201, "{\"id\":42,\"status\":\"ACTIVE\"}"));

        String id = provider.addTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(id).isEqualTo("example.com/42");
        HttpRequest req = sent.get(0);
        assertThat(req.method()).isEqualTo("POST");
        assertThat(req.uri().toString()).isEqualTo(RECORDS);
        assertThat(req.headers().firstValue("Authorization")).contains("Bearer cpk_live_key");
        assertThat(bodyOf(req)).isEqualTo(
                "{\"recordType\":\"TXT\",\"host\":\"_acme-challenge\",\"value\":\"digest\",\"ttl\":60}");
    }

    @Test
    void addTxtRecord_pendingRecordIsStillCreated() throws Exception {
        respond(req -> reply(202, "{\"id\":7,\"status\":\"PENDING\"}"));

        assertThat(provider.addTxtRecord("_acme-challenge.example.com.", "d")).isEqualTo("example.com/7");
    }

    @Test
    void addTxtRecord_walksToTheParentZoneWhenTheSubdomainIsNotOne() throws Exception {
        respond(req -> req.uri().getPath().contains("/zones/www.example.com/")
                ? reply(404, "{\"message\":\"Zone not found\"}")
                : reply(201, "{\"id\":9}"));

        String id = provider.addTxtRecord("_acme-challenge.www.example.com", "d");

        assertThat(id).isEqualTo("example.com/9");
        assertThat(sent).hasSize(2);
        assertThat(sent.get(1).uri().toString()).isEqualTo(RECORDS);
        assertThat(bodyOf(sent.get(1))).contains("\"host\":\"_acme-challenge.www\"");
    }

    @Test
    void addTxtRecord_atAZonesApex_isWrittenToThatZoneAsTheApex() throws Exception {
        respond(req -> reply(201, "{\"id\":5}"));

        String id = provider.addTxtRecord("example.com", "globalsign-domain-verification=abc");

        assertThat(id).isEqualTo("example.com/5");
        assertThat(sent).hasSize(1);
        assertThat(sent.get(0).uri().toString()).isEqualTo(RECORDS);
        assertThat(bodyOf(sent.get(0))).contains("\"host\":\"@\"");
    }

    @Test
    void addTxtRecord_atANameThatIsNotAZone_walksToItsParent() throws Exception {
        respond(req -> req.uri().getPath().contains("/zones/www.example.com/")
                ? reply(404, "{}")
                : reply(201, "{\"id\":6}"));

        String id = provider.addTxtRecord("www.example.com", "globalsign-domain-verification=abc");

        assertThat(id).isEqualTo("example.com/6");
        assertThat(bodyOf(sent.get(1))).contains("\"host\":\"www\"");
    }

    @Test
    void candidateZones_anUnderscoreNameIsNeverAZone() {
        assertThat(CertPingDnsProvider.candidateZones("_acme-challenge.www.example.com"))
                .containsExactly("www.example.com", "example.com");
        assertThat(CertPingDnsProvider.candidateZones("www.example.com"))
                .containsExactly("www.example.com", "example.com");
        assertThat(CertPingDnsProvider.candidateZones("example.com")).containsExactly("example.com");
    }

    @Test
    void addTxtRecord_remembersTheZoneForTheNextRecord() throws Exception {
        respond(req -> req.uri().getPath().contains("/zones/www.example.com/")
                ? reply(404, "{}")
                : reply(201, "{\"id\":1}"));

        provider.addTxtRecord("_acme-challenge.www.example.com", "a");
        provider.addTxtRecord("_acme-challenge.www.example.com", "b");

        assertThat(sent).hasSize(3);
    }

    @Test
    void addTxtRecord_noZoneAnywhere_isZoneNotFound() throws Exception {
        respond(req -> reply(404, "{}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.a.example.com", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_ZONE_NOT_FOUND"));
        assertThat(sent).extracting(r -> r.uri().getPath()).containsExactly(
                "/api/v1/domains/token-api/dns/zones/a.example.com/records",
                "/api/v1/domains/token-api/dns/zones/example.com/records");
    }

    @Test
    void addTxtRecord_forbiddenStopsTheWalk() throws Exception {
        respond(req -> reply(403, "{\"message\":\"This API key does not cover this zone.\"}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.www.example.com", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("does not cover this zone")
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
        assertThat(sent).hasSize(1);
    }

    @Test
    void addTxtRecord_unauthorized_isAuthFailed() throws Exception {
        respond(req -> reply(401, "{}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    void addTxtRecord_duplicateValue_isLookedUpSoItsCleanupDeletesIt() throws Exception {
        respond(req -> switch (req.method()) {
            case "POST" -> duplicate();
            case "GET" -> reply(200, "{\"items\":[{\"id\":76,\"value\":\"other\"},{\"id\":77,\"value\":\"d\"}],"
                    + "\"nextCursor\":null}");
            default -> reply(204, "");
        });

        String id = provider.addTxtRecord("_acme-challenge.example.com", "d");

        assertThat(id).isEqualTo("example.com/77");
        assertThat(sent.get(1).uri().toString()).isEqualTo(RECORDS + "?type=TXT&name=_acme-challenge&size=100");
        provider.deleteTxtRecord("_acme-challenge.example.com", id);
        assertThat(sent.get(2).method()).isEqualTo("DELETE");
        assertThat(sent.get(2).uri().toString()).isEqualTo(RECORDS + "/77");
    }

    @Test
    void addTxtRecord_duplicateTheKeyCannotRead_returnsMarkerThatCleanupSkips() throws Exception {
        respond(req -> "POST".equals(req.method()) ? duplicate()
                : reply(403, "{\"message\":\"This API key lacks the dns:read permission\"}"));

        String id = provider.addTxtRecord("_acme-challenge.example.com", "d");

        assertThat(id).startsWith("existing-");
        provider.deleteTxtRecord("_acme-challenge.example.com", id);
        assertThat(sent).hasSize(2);
    }

    @Test
    void addTxtRecord_duplicateNotAmongTheRecordsRead_returnsMarker() throws Exception {
        respond(req -> "POST".equals(req.method()) ? duplicate()
                : reply(200, "{\"items\":[{\"id\":76,\"value\":\"other\"}],\"nextCursor\":null}"));

        assertThat(provider.addTxtRecord("_acme-challenge.example.com", "d")).startsWith("existing-");
    }

    @Test
    void addRecord_duplicateCname_matchesTheTargetIgnoringCaseAndTheTrailingDot() throws Exception {
        respond(req -> "POST".equals(req.method())
                ? reply(409, "{\"message\":\"A CNAME record at _0a1b with this value already exists.\"}")
                : reply(200, "{\"items\":[{\"id\":81,\"value\":\"AA.bb.dcv.example.\"}],\"nextCursor\":null}"));

        assertThat(provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example"))
                .isEqualTo("example.com/81");
        assertThat(sent.get(1).uri().toString()).isEqualTo(RECORDS + "?type=CNAME&name=_0a1b&size=100");
    }

    @Test
    void addTxtRecord_zoneNotServiceable_isPermanentNotAnExistingRecord() throws Exception {
        respond(req -> reply(409,
                "{\"message\":\"Domain example.com is not in a serviceable state (status DELEGATION_PENDING)\"}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("not in a serviceable state")
                .extracting("errorCode").isEqualTo("DNS_ZONE_NOT_SERVICEABLE");
    }

    @Test
    void addTxtRecord_cnameAtTheChallengeName_isPermanentNotAnExistingRecord() throws Exception {
        respond(req -> reply(409,
                "{\"message\":\"A CNAME record at _acme-challenge cannot share its name with other records.\"}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("CNAME")
                .extracting("errorCode").isEqualTo("DNS_PROVIDER_ERROR");
    }

    @Test
    void addTxtRecord_challengeLimit_isPermanent() throws Exception {
        respond(req -> reply(422, "{\"message\":\"maximum of 20 ACME challenge records\"}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("maximum of 20");
    }

    @Test
    void addTxtRecord_throttled_isRetryableWithRetryAfter() throws Exception {
        respond(req -> reply(429, "{}", Map.of("Retry-After", List.of("12"))));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void addTxtRecord_serverError_isTransient() throws Exception {
        respond(req -> reply(500, "{}"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "d"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void deleteTxtRecord_deletesTheRecordInItsZone() throws Exception {
        respond(req -> reply(204, ""));

        provider.deleteTxtRecord("_acme-challenge.www.example.com", "example.com/42");

        assertThat(sent).hasSize(1);
        assertThat(sent.get(0).method()).isEqualTo("DELETE");
        assertThat(sent.get(0).uri().toString()).isEqualTo(RECORDS + "/42");
        assertThat(sent.get(0).headers().firstValue("Authorization")).contains("Bearer cpk_live_key");
    }

    @Test
    void deleteTxtRecord_failureIsNotFatal() throws Exception {
        respond(req -> reply(500, "{}"));

        provider.deleteTxtRecord("_acme-challenge.example.com", "example.com/42");
        provider.deleteTxtRecord("_acme-challenge.example.com", "not-an-id");

        assertThat(sent).hasSize(1);
    }

    @Test
    void deleteTxtRecord_throttled_isRetryable() throws Exception {
        respond(req -> reply(429, "{}"));

        assertThatThrownBy(() -> provider.deleteTxtRecord("_acme-challenge.example.com", "example.com/42"))
                .isInstanceOf(RetryableAgentException.class);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private record Reply(int status, String body, Map<String, List<String>> headers) {}

    private static Reply duplicate() {
        return reply(409, "{\"message\":\"A TXT record at _acme-challenge with this value already exists.\"}");
    }

    private static Reply reply(int status, String body) {
        return new Reply(status, body, Map.of());
    }

    private static Reply reply(int status, String body, Map<String, List<String>> headers) {
        return new Reply(status, body, headers);
    }

    @SuppressWarnings("unchecked")
    private void respond(Function<HttpRequest, Reply> server) throws Exception {
        HttpClient client = mock(HttpClient.class);
        lenient().when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(inv -> {
                    HttpRequest req = inv.getArgument(0);
                    sent.add(req);
                    Reply r = server.apply(req);
                    HttpResponse<String> resp = mock(HttpResponse.class);
                    lenient().when(resp.statusCode()).thenReturn(r.status());
                    lenient().when(resp.body()).thenReturn(r.body());
                    lenient().when(resp.headers()).thenReturn(HttpHeaders.of(r.headers(), (a, b) -> true));
                    return resp;
                });
        ReflectionTestUtils.setField(provider, "httpClient", client);
    }

    @Test
    void addRecord_cname_postsTheTargetAsACnameAtTheHostInItsZone() throws Exception {
        respond(req -> reply(201, "{\"id\":43,\"status\":\"ACTIVE\"}"));

        String id = provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example");

        assertThat(id).isEqualTo("example.com/43");
        assertThat(sent.get(0).uri().toString()).isEqualTo(RECORDS);
        assertThat(bodyOf(sent.get(0))).isEqualTo(
                "{\"recordType\":\"CNAME\",\"host\":\"_0a1b\",\"value\":\"aa.bb.dcv.example\",\"ttl\":60}");
    }
}
