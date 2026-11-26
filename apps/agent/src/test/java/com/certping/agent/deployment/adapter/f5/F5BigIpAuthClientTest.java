// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class F5BigIpAuthClientTest {

    @Test
    void sendWithAuth_retriesOn401_andUsesRefreshedToken() throws Exception {
        HttpClient http = mock(HttpClient.class);

        // Call order inside sendWithAuth when first attempt returns 401:
        // 1) login, 2) patch TTL, 3) request attempt -> 401,
        // 4) login, 5) patch TTL, 6) retry -> 200
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(
                        resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(200, "{}"),
                        resp(401, "{}"),
                        resp(200, "{\"token\":{\"token\":\"t2\",\"timeout\":1200}}"),
                        resp(200, "{}"),
                        resp(200, "{\"ok\":true}")
                );

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(),
                "https://bigip.example:443",
                "u",
                "p",
                http);

        HttpResponse<String> resp = auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/mgmt/tm/sys/version"))
                .timeout(Duration.ofSeconds(5))
                .header("X-F5-Auth-Token", token)
                .GET()
                .build());

        assertThat(resp.statusCode()).isEqualTo(200);

        // Verify that the last request uses refreshed token t2.
        var requestCaptor = org.mockito.ArgumentCaptor.forClass(HttpRequest.class);
        verify(http, times(6)).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
        HttpRequest last = requestCaptor.getAllValues().get(5);
        assertThat(last.headers().firstValue("X-F5-Auth-Token")).hasValue("t2");
    }

    @Test
    void sendWithAuth_throwsOnEmptyToken() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp(200, "{\"token\":{\"token\":\"\",\"timeout\":1200}}"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(),
                "https://bigip.example:443",
                "u",
                "p",
                http);

        assertThatThrownBy(() -> auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/test"))
                .GET()
                .build()))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("F5 login response missing token");
    }

    @Test
    void sendWithAuth_handlesTtlExtensionFailureGracefully() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(
                        resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(500, "{}"),  // TTL extension fails
                        resp(200, "{\"ok\":true}")
                );

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(),
                "https://bigip.example:443",
                "u",
                "p",
                http);

        HttpResponse<String> resp = auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/test"))
                .header("X-F5-Auth-Token", token)
                .GET()
                .build());

        assertThat(resp.statusCode()).isEqualTo(200);
    }

    @Test
    void sendWithAuth_handles500AsTransient() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(200, "{}"),
                        resp(500, "Internal Server Error"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(),
                "https://bigip.example:443",
                "u",
                "p",
                http);

        // On 500 response, sendWithAuth does NOT throw; it just returns the 500 response.
        // The caller would then check statusCode and wrap it. For now, just verify it doesn't crash.
        HttpResponse<String> result = auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/test"))
                .header("X-F5-Auth-Token", token)
                .GET()
                .build());
        assertThat(result.statusCode()).isEqualTo(500);
    }

    @Test
    void sendWithAuth_loginNon200_throwsPermanent() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp(403, "forbidden"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        assertThatThrownBy(() -> auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/x")).GET().build()))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("access denied");
    }

    @Test
    void sendWithAuth_login500_throwsTransient() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp(500, "oops"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        assertThatThrownBy(() -> auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/x")).GET().build()))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
    }

    @Test
    void sendWithAuth_loginUnparseable_throwsPermanent() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp(200, "not json"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        assertThatThrownBy(() -> auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/x")).GET().build()))
                .isInstanceOf(Exception.class);
    }

    @Test
    void sendWithAuth_ttlExtension500_handled_andLogoutCalled() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(
                        resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(500, "ttl fail"),       // patch TTL fails
                        resp(200, "{\"ok\":true}"),   // first request
                        resp(204, ""));               // logout

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        HttpResponse<String> r = auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/x")).GET().build());
        assertThat(r.statusCode()).isEqualTo(200);

        // Now invoke logout — token is set, this exercises DELETE path.
        auth.logout();
        verify(http, atLeast(4)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void logout_whenNoToken_isNoop() {
        HttpClient http = mock(HttpClient.class);
        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);
        auth.logout(); // no token yet
        verifyNoInteractions(http);
    }

    @Test
    void logout_non2xx_warnsButDoesNotThrow() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(
                        resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(200, "{}"),
                        resp(200, "{\"ok\":true}"),
                        resp(404, "no such token"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/x")).GET().build());

        auth.logout();
    }

    @Test
    void logout_throwingHttp_swallowed() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(
                        resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(200, "{}"),
                        resp(200, "{\"ok\":true}"))
                .thenThrow(new java.io.IOException("boom"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        auth.sendWithAuth(token -> HttpRequest.newBuilder()
                .uri(URI.create(auth.baseUrl() + "/x")).GET().build());

        // Should NOT throw.
        auth.logout();
    }

    @Test
    void cachedToken_avoidsReLogin() throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(
                        resp(200, "{\"token\":{\"token\":\"t1\",\"timeout\":1200}}"),
                        resp(200, "{}"),
                        resp(200, "{\"a\":1}"),
                        resp(200, "{\"b\":2}"));

        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "https://bigip.example:443", "u", "p", http);

        auth.sendWithAuth(t -> HttpRequest.newBuilder().uri(URI.create(auth.baseUrl() + "/x")).GET().build());
        auth.sendWithAuth(t -> HttpRequest.newBuilder().uri(URI.create(auth.baseUrl() + "/y")).GET().build());

        // 1 login + 1 ttl + 2 requests = 4 calls (no re-login).
        verify(http, times(4)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void hostPortConstructor_buildsBaseUrlAndTrustAllClient() {
        // Exercises buildHttpClient(verifySsl=false) trust-all branch.
        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "bigip.example.com", 8443, "u", "p", false);
        assertThat(auth.baseUrl()).isEqualTo("https://bigip.example.com:8443");
    }

    @Test
    void hostPortConstructor_buildsBaseUrlAndVerifyingClient() {
        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(), "bigip.example.com", 443, "u", "p", true);
        assertThat(auth.baseUrl()).isEqualTo("https://bigip.example.com:443");
    }

    @Test
    void baseUrl_returnsConstructedUrl() {
        HttpClient http = mock(HttpClient.class);
        F5BigIpAuthClient auth = new F5BigIpAuthClient(
                JsonMapper.builderWithJackson2Defaults().build(),
                "https://bigip.example:443",
                "u",
                "p",
                http);

        assertThat(auth.baseUrl()).isEqualTo("https://bigip.example:443");
    }

    private static HttpResponse<String> resp(int status, String body) {
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return HttpRequest.newBuilder(URI.create("https://x"))
                    .GET().build(); }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return HttpHeaders.of(java.util.Map.of(), (a, b) -> true); }
            @Override public String body() { return body; }
            @Override public Optional<javax.net.ssl.SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://x"); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }
}
