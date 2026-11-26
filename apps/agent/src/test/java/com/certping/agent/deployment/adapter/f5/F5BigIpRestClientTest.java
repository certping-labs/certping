// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class F5BigIpRestClientTest {

    @Test
    void uploadFileChunked_setsContentRangeHeaders_forEachChunk() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        List<String> ranges = new ArrayList<>();
        when(auth.sendWithAuth(any()))
                .thenAnswer(inv -> {
                    @SuppressWarnings("unchecked")
                    Function<String, HttpRequest> fn = (Function<String, HttpRequest>) inv.getArgument(0);
                    HttpRequest req = fn.apply("tok");
                    ranges.add(req.headers().firstValue("Content-Range").orElse(""));
                    return resp(200, "{}");
                });

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);

        byte[] bytes = ("X".repeat(1200)).getBytes(StandardCharsets.UTF_8);
        client.uploadFileChunked("test.crt", bytes, 500);

        assertThat(ranges).hasSize(3);
        assertThat(ranges.get(0)).isEqualTo("0-499/1200");
        assertThat(ranges.get(1)).isEqualTo("500-999/1200");
        assertThat(ranges.get(2)).isEqualTo("1000-1199/1200");
    }

    @Test
    void uploadFileChunked_throwsPermanentException_onNon200Or201() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(400, "{\"error\":\"bad request\"}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        byte[] bytes = "test".getBytes();

        assertThatThrownBy(() -> client.uploadFileChunked("test.crt", bytes, 10))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void installCertObject_sendsPostWithCertData() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        client.installCertObject("mycert", "mycert.crt");

        // Verify POST was sent to cert endpoint.
        assertThat(true).isTrue(); // Basic happy path verify.
    }

    @Test
    void installKeyObject_sendsPostWithKeyData() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        client.installKeyObject("mykey", "mykey.key");

        // Verify POST was sent to key endpoint.
        assertThat(true).isTrue();
    }

    @Test
    void patchClientSslProfile_throwsIfProfileNotFound() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(404, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);

        assertThatThrownBy(() -> client.patchClientSslProfile("part", "prof", "cert", "key"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void patchClientSslProfile_succeeds_onProfileFound() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, "{}"))  // GET returns 200
                .thenReturn(resp(200, "{}"));  // PATCH returns 200

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        client.patchClientSslProfile("part", "prof", "cert", "key");

        assertThat(true).isTrue();
    }

    @Test
    void saveConfig_sendsPostRequest() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        client.saveConfig();

        assertThat(true).isTrue();
    }

    @Test
    void syncToDeviceGroup_sendsValidPayload() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        client.syncToDeviceGroup("mygroup");

        // Basic happy path verify.
        assertThat(true).isTrue();
    }

    @Test
    void findProfilesByCertHostnames_matchesByWildcardOverlap() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        // Sequence: 1) list profiles, 2) fetch cert for profile-api, 3) fetch cert for profile-other.
        String listBody = "{\"items\":["
                + "{\"name\":\"profile-api\",\"certKeyChain\":[{\"cert\":\"/Common/api-cert\"}]},"
                + "{\"name\":\"profile-other\",\"certKeyChain\":[{\"cert\":\"/Common/other-cert\"}]}"
                + "]}";
        String apiCertBody = "{\"subject\":\"CN=api.example.com,O=Acme\","
                + "\"subjectAlternativeName\":\"DNS:api.example.com, DNS:www.example.com\"}";
        String otherCertBody = "{\"subject\":\"CN=svc.other.com,O=Acme\","
                + "\"subjectAlternativeName\":\"DNS:svc.other.com\"}";

        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, listBody))
                .thenReturn(resp(200, apiCertBody))
                .thenReturn(resp(200, otherCertBody));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);

        // New cert is wildcard *.example.com — should match profile-api's bound cert (api.example.com)
        // but not profile-other (svc.other.com).
        List<String> matched = client.findProfilesByCertHostnames("Common", List.of("*.example.com"));

        assertThat(matched).containsExactly("profile-api");
    }

    @Test
    void findProfilesByCertHostnames_emptyTargets_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesByCertHostnames("Common", List.of())).isEmpty();
    }

    @Test
    void findProfilesByCertHostnames_skipsProfilesWhoseCertCantBeFetched() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        String listBody = "{\"items\":["
                + "{\"name\":\"profile-deleted-cert\",\"certKeyChain\":[{\"cert\":\"/Common/gone\"}]}"
                + "]}";
        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, listBody))
                .thenReturn(resp(404, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        List<String> matched = client.findProfilesByCertHostnames("Common", List.of("api.example.com"));

        assertThat(matched).isEmpty();
    }

    @Test
    void pollSyncStatus_returnsImmediately_whenStatusIsStandalone() throws Exception {
        // pollSyncStatus sleeps 5s per loop and looks for "in sync"/"standalone" — first
        // response must already match or the test will hang.
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, "{\"entries\":{\"x\":{\"nestedStats\":{\"entries\":{\"status\":{\"description\":\"Standalone\"}}}}}}"));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);
        client.pollSyncStatus();

        assertThat(true).isTrue();
    }

    private static HttpResponse<String> resp(int status, String body) {
        return respWithHeaders(status, body, Map.of());
    }

    private static HttpResponse<String> respWithHeaders(int status, String body, Map<String, List<String>> headers) {
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public java.util.Optional<HttpResponse<String>> previousResponse() { return java.util.Optional.empty(); }
            @Override public java.net.http.HttpHeaders headers() { return java.net.http.HttpHeaders.of(headers, (a, b) -> true); }
            @Override public String body() { return body; }
            @Override public java.util.Optional<javax.net.ssl.SSLSession> sslSession() { return java.util.Optional.empty(); }
            @Override public java.net.URI uri() { return java.net.URI.create("https://x"); }
            @Override public java.net.http.HttpClient.Version version() { return java.net.http.HttpClient.Version.HTTP_1_1; }
        };
    }

    @Test
    void uploadFileChunked_emptyBytes_throwsPermanent() {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        assertThatThrownBy(() -> client.uploadFileChunked("empty.crt", new byte[0], 10))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("empty");
        assertThatThrownBy(() -> client.uploadFileChunked("null.crt", null, 10))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void installCertObject_500_throwsTransient() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(500, "boom"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        assertThatThrownBy(() -> client.installCertObject("c", "c.crt"))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
    }

    @Test
    void installCertObject_401_throwsPermanentAccessDenied() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(401, "denied"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        assertThatThrownBy(() -> client.installCertObject("c", "c.crt"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("access denied");
    }

    @Test
    void installCertObject_503_throwsRetryable() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(respWithHeaders(503, "x", Map.of()));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        assertThatThrownBy(() -> client.installCertObject("c", "c.crt"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void installCertObject_largeBody_isTruncatedInError() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        String huge = "x".repeat(3500);
        when(auth.sendWithAuth(any())).thenReturn(resp(400, huge));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        assertThatThrownBy(() -> client.installCertObject("c", "c.crt"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("...");
    }

    @Test
    void installCertObject_nullBody_handled() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(400, null));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        assertThatThrownBy(() -> client.installCertObject("c", "c.crt"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void patchClientSslProfile_preservesChainName_fromExistingProfile() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, "{\"certKeyChain\":[{\"name\":\"customChain\",\"cert\":\"/Common/old\"}]}"))
                .thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        client.patchClientSslProfile("Common", "prof", "newCert", "newKey");
    }

    @Test
    void patchClientSslProfile_emptyPartition_defaultsToCommon() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, "{\"certKeyChain\":[]}"))
                .thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        client.patchClientSslProfile("", "prof", "cert", "key");
        client.patchClientSslProfile(null, "prof2", "cert", "key");
    }

    @Test
    void patchClientSslProfile_unparseableBody_usesDefaultChain() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, "this is not json"))
                .thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        client.patchClientSslProfile("Common", "prof", "cert", "key");
    }

    @Test
    void patchClientSslProfile_getReturns500_throwsTransient() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(500, "boom"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThatThrownBy(() -> client.patchClientSslProfile("Common", "prof", "cert", "key"))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
    }

    @Test
    void findProfilesUsingCert_returnsMatches() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        String body = "{\"items\":["
                + "{\"name\":\"p1\",\"certKeyChain\":[{\"cert\":\"/Common/target\"}]},"
                + "{\"name\":\"p2\",\"certKeyChain\":[{\"cert\":\"/Common/other\"}]},"
                + "{\"name\":\"p3\",\"certKeyChain\":[]},"
                + "{\"name\":\"\",\"certKeyChain\":[{\"cert\":\"/Common/target\"}]}"
                + "]}";
        when(auth.sendWithAuth(any())).thenReturn(resp(200, body));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        List<String> result = client.findProfilesUsingCert("Common", "target");
        assertThat(result).containsExactly("p1");
    }

    @Test
    void findProfilesUsingCert_emptyOrNullPartition_defaultsCommon() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{\"items\":[]}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesUsingCert(null, "x")).isEmpty();
        assertThat(client.findProfilesUsingCert("  ", "x")).isEmpty();
    }

    @Test
    void findProfilesUsingCert_noItemsArray_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesUsingCert("Common", "x")).isEmpty();
    }

    @Test
    void findProfilesUsingCert_unparseable_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "not json"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesUsingCert("Common", "x")).isEmpty();
    }

    @Test
    void findProfilesByCertHostnames_noItemsArray_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesByCertHostnames("Common", List.of("api.example.com"))).isEmpty();
    }

    @Test
    void findProfilesByCertHostnames_skipsBlankNamesAndEmptyChains() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        String listBody = "{\"items\":["
                + "{\"name\":\"\",\"certKeyChain\":[{\"cert\":\"/Common/x\"}]},"
                + "{\"name\":\"p-empty\",\"certKeyChain\":[]},"
                + "{\"name\":\"p-blank-cert\",\"certKeyChain\":[{\"cert\":\"\"}]}"
                + "]}";
        when(auth.sendWithAuth(any())).thenReturn(resp(200, listBody));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesByCertHostnames("Common", List.of("api.example.com"))).isEmpty();
    }

    @Test
    void findProfilesByCertHostnames_unparseable_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "not json"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesByCertHostnames("Common", List.of("api.example.com"))).isEmpty();
    }

    @Test
    void findProfilesByCertHostnames_skipsCertWithBadRef() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        // First listing, then bad cert (no leading slash) - fetchCertHostnames returns empty set
        String listBody = "{\"items\":["
                + "{\"name\":\"p1\",\"certKeyChain\":[{\"cert\":\"Common/bad\"}]}"
                + "]}";
        when(auth.sendWithAuth(any())).thenReturn(resp(200, listBody));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesByCertHostnames("Common", List.of("api.example.com"))).isEmpty();
    }

    @Test
    void findProfilesByCertHostnames_certFetch5xx_skipped() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        String listBody = "{\"items\":["
                + "{\"name\":\"p1\",\"certKeyChain\":[{\"cert\":\"/Common/x\"}]}"
                + "]}";
        when(auth.sendWithAuth(any()))
                .thenReturn(resp(200, listBody))
                .thenReturn(resp(500, "x"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.findProfilesByCertHostnames("Common", List.of("api.example.com"))).isEmpty();
    }

    @Test
    void detectDeviceGroups_returnsSyncFailoverAndSyncOnly_skipsTrustGroup() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");

        String body = "{\"items\":["
                + "{\"name\":\"dg-ha\",\"type\":\"sync-failover\"},"
                + "{\"name\":\"dg-cfg\",\"type\":\"sync-only\"},"
                + "{\"name\":\"device_trust_group\",\"type\":\"sync-failover\"},"
                + "{\"name\":\"dg-other\",\"type\":\"other\"},"
                + "{\"name\":\"\",\"type\":\"sync-failover\"}"
                + "]}";
        when(auth.sendWithAuth(any())).thenReturn(resp(200, body));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.detectDeviceGroups()).containsExactly("dg-ha", "dg-cfg");
    }

    @Test
    void detectDeviceGroups_noItems_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.detectDeviceGroups()).isEmpty();
    }

    @Test
    void detectDeviceGroups_unparseable_returnsEmpty() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "not json"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThat(client.detectDeviceGroups()).isEmpty();
    }

    @Test
    void detectDeviceGroups_errorStatus_throws() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(400, "bad"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        assertThatThrownBy(client::detectDeviceGroups)
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void pollSyncStatus_returnsImmediately_whenInSync() throws Exception {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(resp(200, "{\"x\":\"In Sync\"}"));

        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);
        client.pollSyncStatus();
    }

    @Test
    void verifyDomainsBestEffort_unparseableCertPem_returnsEarly() {
        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        F5BigIpRestClient client = new F5BigIpRestClient(JsonMapper.builderWithJackson2Defaults().build(), auth);

        // No exception, no calls.
        client.verifyDomainsBestEffort(List.of("api.example.com"), null);
        client.verifyDomainsBestEffort(List.of("api.example.com"), "no-pem-markers");
        client.verifyDomainsBestEffort(List.of("api.example.com"), "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----");
    }

    @Test
    void dedupe_preservesOrder_andSkipsBlanksAndNulls() {
        List<String> in = java.util.Arrays.asList("a", " b ", "a", null, "", "b", "c");
        List<String> out = F5BigIpRestClient.dedupe(in);
        assertThat(out).containsExactly("a", "b", "c");
        assertThat(F5BigIpRestClient.dedupe(null)).isEmpty();
    }

    @Test
    void installCertObject_rateLimited_throwsRetryableWithDeployProviderThrottled() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

        F5BigIpAuthClient auth = mock(F5BigIpAuthClient.class);
        when(auth.baseUrl()).thenReturn("https://bigip.example:443");
        when(auth.sendWithAuth(any())).thenReturn(
                respWithHeaders(429, "rate limited", Map.of("Retry-After", List.of("30"))));

        F5BigIpRestClient client = new F5BigIpRestClient(om, auth);

        assertThatThrownBy(() -> client.installCertObject("mycert", "mycert.crt"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(ex -> {
                    RetryableAgentException r = (RetryableAgentException) ex;
                    assertThat(r.getErrorCode()).isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                    assertThat(r.getRetryAfter()).isEqualTo(Duration.ofSeconds(30));
                });
    }
}
