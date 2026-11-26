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

import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class NamecheapDnsProviderTest {

    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> getHostsResponse;
    @Mock private HttpResponse<String> setHostsResponse;

    private NamecheapDnsProvider provider;

    @BeforeEach
    void setUp() {
        provider = new NamecheapDnsProvider("api-user", "api-key", "username", "203.0.113.10");
        ReflectionTestUtils.setField(provider, "httpClient", mockHttpClient);
    }

    @Test
    void constructor_blankClientIp_throwsPermanentException() {
        assertThatThrownBy(() -> new NamecheapDnsProvider("api-user", "api-key", "username", " "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_preservesExistingRecordsAndAppendsAcmeTxt() throws Exception {
        givenNamecheapResponses(existingHostsXml(), successXml());

        String recordId = provider.addTxtRecord("_acme-challenge.api.example.com", "digest-value");

        assertThat(recordId).startsWith("_acme-challenge.api:example.com:");

        List<HttpRequest> requests = sentRequests();
        Map<String, String> setHostsQuery = queryParams(requests.get(1));
        assertThat(setHostsQuery)
                .containsEntry("Command", "namecheap.domains.dns.setHosts")
                .containsEntry("SLD", "example")
                .containsEntry("TLD", "com")
                .containsEntry("HostName1", "@")
                .containsEntry("RecordType1", "A")
                .containsEntry("Address1", "1.2.3.4")
                .containsEntry("HostName2", "_acme-challenge.api")
                .containsEntry("RecordType2", "TXT")
                .containsEntry("Address2", "digest-value")
                .containsEntry("TTL2", "60");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_existingTxt_doesNotCallSetHosts() throws Exception {
        givenNamecheapResponses(hostsXmlWithAcmeTxt());

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "existing-digest");

        assertThat(recordId).startsWith("_acme-challenge:example.com:");
        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_authHttpStatus_throwsPermanentException() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(403);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimitedHttpStatus_throwsRetryableException() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(429);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"))
                .hasMessageContaining("rate-limited");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimitedHttpStatusWithRetryAfter_preservesRetryAfter() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(429);
        when(getHostsResponse.headers()).thenReturn(java.net.http.HttpHeaders.of(
                Map.of("Retry-After", List.of("45")), (name, value) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getRetryAfter())
                        .isEqualTo(Duration.ofSeconds(45)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_apiAuthError_throwsPermanentException() throws Exception {
        givenNamecheapResponses(errorXml("1017105", "Parameter ClientIP is disabled or locked"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_apiRateLimitError_throwsRetryableException() throws Exception {
        givenNamecheapResponses(errorXml("3050900", "Too many requests. Please retry later."));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"))
                .hasMessageContaining("rate limited");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_domainNotFound_throwsPermanentException() throws Exception {
        givenNamecheapResponses(errorXml("2019166", "Domain not found"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_ZONE_NOT_FOUND"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_notUsingNamecheapDns_throwsPermanentException() throws Exception {
        givenNamecheapResponses(notUsingNamecheapDnsXml());

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_ZONE_NOT_FOUND"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_setHostsNotSuccessful_throwsTransientException() throws Exception {
        givenNamecheapResponses(existingHostsXml(), setHostsFailureXml());

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_removesOnlyMatchingAcmeTxt() throws Exception {
        givenNamecheapResponses(hostsXmlWithAcmeTxt(), successXml());
        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "existing-digest");
        reset(mockHttpClient);
        givenNamecheapResponses(hostsXmlWithAcmeTxt(), successXml());

        provider.deleteTxtRecord("_acme-challenge.example.com", recordId);

        List<HttpRequest> requests = sentRequests();
        Map<String, String> setHostsQuery = queryParams(requests.get(1));
        assertThat(setHostsQuery)
                .containsEntry("HostName1", "@")
                .containsEntry("RecordType1", "A")
                .doesNotContainEntry("HostName2", "_acme-challenge");
    }

    @Test
    void deleteTxtRecord_invalidRecordId_skipsHttpRequest() {
        provider.deleteTxtRecord("_acme-challenge.example.com", "bad-record-id");

        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_httpServerError_throwsTransient() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(500);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_serviceUnavailableHttpStatus_throwsRetryableException() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(503);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_unauthorizedHttpStatus_throwsPermanentException() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "value"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimitErrorMessage_variations() throws Exception {
        // "too many requests" / "rate limit" / "throttle" / "rate-limit" all classify as throttled
        for (String msg : List.of("Too many requests", "rate limit exceeded", "RATE-LIMIT", "throttled")) {
            reset(mockHttpClient, getHostsResponse);
            givenNamecheapResponses(errorXml("3050900", msg));
            assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_genericApiError_throwsTransient() throws Exception {
        givenNamecheapResponses(errorXml("9999", "Generic backend error"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_apiErrorWithNoErrorElement_throwsTransient() throws Exception {
        String body = """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="ERROR">
                  <Errors />
                </ApiResponse>
                """;
        givenNamecheapResponses(body);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "v"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_recordIdDomainMismatch_skipsDeletion() throws Exception {
        // Valid 4-part recordId but encoded for a DIFFERENT domain — provider should warn
        // and skip without ever calling getHosts.
        String otherDomainRecordId = "_acme-challenge:other.com:abc123:somevalue";
        provider.deleteTxtRecord("_acme-challenge.example.com", otherDomainRecordId);
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_recordNotInZone_doesNotCallSetHosts() throws Exception {
        // Encoded for example.com but the zone doesn't contain that TXT — deletion is a no-op
        givenNamecheapResponses(existingHostsXml());

        // craft a valid encoded recordId via addTxtRecord using a different path — use NamecheapRecordId
        // directly to keep the test focused
        com.certping.agent.ssl.dns.NamecheapZoneHost zh =
                com.certping.agent.ssl.dns.NamecheapZoneHost.fromRecordName("_acme-challenge.example.com");
        String recordId = com.certping.agent.ssl.dns.NamecheapRecordId.encode(zh, "different-value");

        provider.deleteTxtRecord("_acme-challenge.example.com", recordId);

        // Only one HTTP call (getHosts) since remainingRecords.size() == records.size() means
        // setHosts is skipped
        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_httpServerErrorOnGetHosts_swallowed() throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(500);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse);

        com.certping.agent.ssl.dns.NamecheapZoneHost zh =
                com.certping.agent.ssl.dns.NamecheapZoneHost.fromRecordName("_acme-challenge.example.com");
        String recordId = com.certping.agent.ssl.dns.NamecheapRecordId.encode(zh, "v");

        // Best-effort delete: TransientAgentException is caught and logged (not re-thrown).
        // RetryableAgentException would be re-thrown; TransientAgentException is treated as non-fatal.
        // Actually — looking at code: catch (Exception e) checks rate-limit then logs and returns.
        // So a TransientAgentException is treated as a regular Exception and swallowed.
        provider.deleteTxtRecord("_acme-challenge.example.com", recordId);
    }

    private void givenNamecheapResponses(String firstBody, String... remainingBodies) throws Exception {
        when(getHostsResponse.statusCode()).thenReturn(200);
        when(getHostsResponse.body()).thenReturn(firstBody);
        if (remainingBodies.length == 0) {
            when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(getHostsResponse);
            return;
        }
        when(setHostsResponse.statusCode()).thenReturn(200);
        when(setHostsResponse.body()).thenReturn(remainingBodies[0]);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(getHostsResponse, setHostsResponse);
    }

    private List<HttpRequest> sentRequests() throws Exception {
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient, atLeastOnce()).send(captor.capture(), any(HttpResponse.BodyHandler.class));
        return captor.getAllValues();
    }

    private Map<String, String> queryParams(HttpRequest request) {
        Map<String, String> params = new HashMap<>();
        for (String pair : request.uri().getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            params.put(key, value);
        }
        return params;
    }

    private String existingHostsXml() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="OK">
                  <Errors />
                  <CommandResponse>
                    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
                      <Host HostId="12" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
                    </DomainDNSGetHostsResult>
                  </CommandResponse>
                </ApiResponse>
                """;
    }

    private String hostsXmlWithAcmeTxt() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="OK">
                  <Errors />
                  <CommandResponse>
                    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
                      <Host HostId="12" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
                      <Host HostId="13" Name="_acme-challenge" Type="TXT" Address="existing-digest" TTL="300" />
                    </DomainDNSGetHostsResult>
                  </CommandResponse>
                </ApiResponse>
                """;
    }

    private String notUsingNamecheapDnsXml() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="OK">
                  <Errors />
                  <CommandResponse>
                    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="false" />
                  </CommandResponse>
                </ApiResponse>
                """;
    }

    private String successXml() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="OK">
                  <Errors />
                  <CommandResponse>
                    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
                  </CommandResponse>
                </ApiResponse>
                """;
    }

    private String setHostsFailureXml() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="OK">
                  <Errors />
                  <CommandResponse>
                    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="false" />
                  </CommandResponse>
                </ApiResponse>
                """;
    }

    private String errorXml(String code, String message) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <ApiResponse Status="ERROR">
                  <Errors>
                    <Error Number="%s">%s</Error>
                  </Errors>
                </ApiResponse>
                """.formatted(code, message);
    }

    @Test
    void addRecord_cname_appendsTheTargetWithItsTrailingDot() throws Exception {
        givenNamecheapResponses(existingHostsXml(), successXml());

        provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example");

        assertThat(queryParams(sentRequests().get(1)))
                .containsEntry("HostName2", "_0a1b")
                .containsEntry("RecordType2", "CNAME")
                .containsEntry("Address2", "aa.bb.dcv.example.");
    }

    @Test
    void addRecord_cnameAlreadyServedWithoutTrailingDot_isNotWrittenAgain() throws Exception {
        givenNamecheapResponses(existingHostsXml().replace("</DomainDNSGetHostsResult>",
                "<Host HostId=\"14\" Name=\"_0a1b\" Type=\"CNAME\" Address=\"AA.bb.dcv.example\" TTL=\"60\" />"
                        + "</DomainDNSGetHostsResult>"));

        provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example");

        assertThat(sentRequests()).hasSize(1);
    }
}
